package org.rtrusttunnel.android;
import android.app.*;
import org.json.*;
import java.util.*;
final class RecoveryDialog {
    static void show(Activity activity,ProfileVault vault,String primaryId) throws Exception {
        JSONObject data=vault.read();ProfileVault.Selection primary=ProfileVault.resolveSelection(data,primaryId);
        ArrayList<String> ids=new ArrayList<>(),names=new ArrayList<>();JSONArray entries=data.getJSONArray("profiles");
        for(int i=0;i<entries.length();i++){JSONObject entry=entries.getJSONObject(i);if(!entry.getString("id").equals(primary.id)){ids.add(entry.getString("id"));names.add(entry.getJSONObject("profile").optString("name",entry.getString("id")));}}
        boolean[] checked=new boolean[ids.size()];JSONObject previous=data.optJSONObject("mobile_recovery");
        if(previous!=null && primary.id.equals(previous.optString("primary"))){JSONArray old=previous.optJSONArray("backups");if(old!=null)for(int i=0;i<old.length();i++){int index=ids.indexOf(old.getString(i));if(index>=0)checked[index]=true;}}
        new AlertDialog.Builder(activity).setTitle(R.string.recovery_title)
            .setMultiChoiceItems(names.toArray(new String[0]),checked,(d,index,on)->checked[index]=on)
            .setNeutralButton(R.string.recovery_disable,(d,w)->{try{vault.edit(v->v.remove("mobile_recovery"));TunnelService.recoverySettingsChanged();}catch(Exception ignored){}})
            .setNegativeButton(android.R.string.cancel,null)
            .setPositiveButton(R.string.recovery_enable,(d,w)->{
                try {
                    if(TunnelService.active)throw new IllegalStateException();
                    JSONArray chosen=new JSONArray();for(int i=0;i<checked.length;i++)if(checked[i])chosen.put(ids.get(i));
                    if(chosen.length()<1 || chosen.length()>3)throw new IllegalArgumentException();
                    JSONObject setting=new JSONObject().put("enabled",true).put("primary",primary.id).put("backups",chosen);
                    vault.edit(v->{v.put("mobile_recovery",setting);new ProfileVault.ConnectionSet(v,primary.id);});
                }catch(Exception error){new AlertDialog.Builder(activity).setMessage(R.string.recovery_invalid).setPositiveButton(android.R.string.ok,null).show();}
            }).show();
    }
}
