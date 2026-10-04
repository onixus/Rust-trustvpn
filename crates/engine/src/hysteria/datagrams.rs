use super::*;
use crate::udp::{self, Datagram};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Instant,
};
struct Registration {
    routes: DatagramRoutes,
    ids: HashSet<u32>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        for id in &self.ids {
            routes.remove(id);
        }
    }
}
struct Flow {
    source: SocketAddr,
    destination: SocketAddr,
    seen: Instant,
}
struct Chunk {
    bytes: Vec<u8>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
struct Fragments {
    _slot: tokio::sync::OwnedSemaphorePermit,
    address: SocketAddr,
    parts: Vec<Option<Chunk>>,
    created: Instant,
}
fn number(data: &[u8], offset: &mut usize) -> Result<usize> {
    let first = *data.get(*offset).ok_or(Error::Protocol)?;
    let count = 1usize << (first >> 6);
    let mut n = (first & 63) as u64;
    *offset += 1;
    for _ in 1..count {
        n = (n << 8) | *data.get(*offset).ok_or(Error::Protocol)? as u64;
        *offset += 1;
    }
    usize::try_from(n).map_err(|_| Error::Protocol)
}
struct Message<'a> {
    id: u32,
    packet: u16,
    index: u8,
    count: u8,
    address: SocketAddr,
    payload: &'a [u8],
}
fn unpack(data: &[u8]) -> Result<Message<'_>> {
    if data.len() < 9 {
        return Err(Error::Protocol);
    }
    let session = u32::from_be_bytes(data[..4].try_into().unwrap());
    let packet = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let fragment = data[6];
    let count = data[7];
    if count == 0 || (count > 1 && fragment >= count) {
        return Err(Error::Protocol);
    }
    let mut offset = 8;
    let len = number(data, &mut offset)?;
    if len > 512 || len > data.len() - offset {
        return Err(Error::Protocol);
    }
    let address = std::str::from_utf8(&data[offset..offset + len])
        .map_err(|_| Error::Protocol)?
        .parse()
        .map_err(|_| Error::Protocol)?;
    offset += len;
    Ok(Message {
        id: session,
        packet,
        index: fragment,
        count,
        address,
        payload: &data[offset..],
    })
}
pub(crate) async fn outgoing(reader: &mut (impl AsyncRead + Unpin)) -> Result<Datagram> {
    let len = reader.read_u32().await? as usize;
    if !(37..=37 + 255 + udp::MAX_DATAGRAM).contains(&len) {
        return Err(Error::Protocol);
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame).await?;
    let app = frame[36] as usize;
    if 37 + app > len || len - 37 - app > udp::MAX_DATAGRAM {
        return Err(Error::Protocol);
    }
    frame.drain(36..37 + app);
    let mut response = (frame.len() as u32).to_be_bytes().to_vec();
    response.extend(frame);
    udp::read(&mut response.as_slice()).await
}
pub(super) async fn open(session: HysteriaSession) -> Result<Tunnel> {
    if !session.0.udp {
        return Err(Error::Unsupported("Hysteria server disabled UDP"));
    }
    let permit = session
        .0
        .udp_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unsupported("Hysteria UDP stream capacity"))?;
    let (io, bridge) = tokio::io::duplex(128 * 1024);
    let pump = tokio::spawn(async move {
        let _permit = permit;
        let _ = relay(session, bridge).await;
    });
    Ok(Tunnel { io, pump })
}
async fn relay(session: HysteriaSession, bridge: DuplexStream) -> Result<()> {
    let mut registration = Registration {
        routes: session.0.routes.clone(),
        ids: HashSet::new(),
    };
    let mut flows: HashMap<u32, Flow> = HashMap::new();
    let mut fragments: HashMap<(u32, u16), Fragments> = HashMap::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Bytes>(128);
    let (mut read, mut write) = tokio::io::split(bridge);
    let mut request = Box::pin(outgoing(&mut read));
    let mut packet = 0u16;
    let mut maintenance = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _=maintenance.tick()=>{
                let expired:Vec<_>=flows.iter().filter(|(_,flow)|flow.seen.elapsed()>Duration::from_secs(60)).map(|(id,_)|*id).collect();
                for id in expired{flows.remove(&id);registration.ids.remove(&id);session.0.routes.lock().unwrap_or_else(|e|e.into_inner()).remove(&id);}
                fragments.retain(|(id,_),f|flows.contains_key(id)&&f.created.elapsed()<Duration::from_secs(5));
                session.health().await?;
            }
            data=&mut request=>{
                let d=data?;drop(request);request=Box::pin(outgoing(&mut read));
                let id=if let Some((&id,flow))=flows.iter_mut().find(|(_,f)|f.source==d.source&&f.destination==d.destination){flow.seen=Instant::now();id}else{
                    if flows.len()>=256{continue}
                    let id=session.0.next_id.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1)).map_err(|_|Error::Protocol)?;
                    let mut routes=session.0.routes.lock().unwrap_or_else(|e|e.into_inner());routes.retain(|_,s|!s.is_closed());if routes.len()>=1024{continue}
                    routes.insert(id,sender.clone());registration.ids.insert(id);flows.insert(id,Flow{source:d.source,destination:d.destination,seen:Instant::now()});id
                };
                let address=d.destination.to_string();let mut header=Vec::new();varint(address.len() as u64,&mut header)?;header.extend(address.as_bytes());
                let mtu=session.0.connection.max_datagram_size().ok_or(Error::Protocol)?;
                let size=mtu.checked_sub(8+header.len()).filter(|s|*s>0).ok_or(Error::Protocol)?;
                let count=d.payload.len().div_ceil(size).max(1);if count>255{continue}packet=packet.wrapping_add(1);
                for index in 0..count {
                    let mut data=Vec::with_capacity(mtu);data.extend(id.to_be_bytes());data.extend(packet.to_be_bytes());data.push(index as u8);data.push(count as u8);data.extend(&header);
                    let start=(index*size).min(d.payload.len());let end=((index+1)*size).min(d.payload.len());data.extend(&d.payload[start..end]);
                    session.0.connection.send_datagram_wait(Bytes::from(data)).await.map_err(|_|Error::Io)?;
                }
            }
            incoming=receiver.recv()=>{
                let Some(data)=incoming else{return Err(Error::Connect)};
                let Ok(Message{id,packet,index,count,address,payload})=unpack(&data) else{continue};
                let Some(flow)=flows.get_mut(&id) else{continue};if address!=flow.destination{continue}flow.seen=Instant::now();
                let payload=if count==1{payload.to_vec()}else{
                    // Hard bound independent of peer-controlled IDs/counts; expire fragments before accounting.
                    fragments.retain(|_,f|f.created.elapsed()<Duration::from_secs(5));
                    if let std::collections::hash_map::Entry::Vacant(entry)=fragments.entry((id,packet)) {
                        let Ok(slot)=session.0.fragment_slots.clone().try_acquire_owned() else{continue};
                        entry.insert(Fragments{_slot:slot,address,parts:(0..count).map(|_|None).collect(),created:Instant::now()});
                    }
                    let f=fragments.get_mut(&(id,packet)).unwrap();
                    if f.address!=address||f.parts.len()!=count as usize {fragments.remove(&(id,packet));continue}
                    if f.parts[index as usize].is_some(){continue}
                    let Ok(permit)=session.0.fragment_bytes.clone().try_acquire_many_owned(payload.len() as u32) else{continue};
                    f.parts[index as usize]=Some(Chunk{bytes:payload.to_vec(),_permit:permit});
                    if f.parts.iter().any(Option::is_none){continue}
                    let f=fragments.remove(&(id,packet)).unwrap();let len:usize=f.parts.iter().flatten().map(|p|p.bytes.len()).sum();if len>udp::MAX_DATAGRAM{continue}
                    f.parts.into_iter().flatten().flat_map(|c|c.bytes).collect()
                };
                if payload.len()>udp::MAX_DATAGRAM{continue}
                let mut frame=udp::encode(&Datagram{source:address,destination:flow.source,payload},"")?;
                frame.remove(40);let len=(frame.len()-4) as u32;frame[..4].copy_from_slice(&len.to_be_bytes());
                tokio::time::timeout(Duration::from_secs(10),write.write_all(&frame)).await.map_err(|_|Error::Timeout)??;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_datagrams_are_rejected_before_reassembly() {
        for bytes in [vec![], vec![0; 8], vec![0; 9], vec![255; 100]] {
            assert!(unpack(&bytes).is_err())
        }
    }
    #[tokio::test]
    async fn outgoing_adapter_preserves_max_udp_payload() {
        let d = Datagram {
            source: "10.0.0.1:1234".parse().unwrap(),
            destination: "192.0.2.1:53".parse().unwrap(),
            payload: vec![42; udp::MAX_DATAGRAM],
        };
        let frame = udp::encode(&d, "rtrust-tun").unwrap();
        assert_eq!(outgoing(&mut frame.as_slice()).await.unwrap(), d)
    }
}
