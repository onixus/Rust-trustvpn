package org.rtrusttunnel.android;

import java.io.*;
import java.nio.charset.StandardCharsets;

final class DiagnosticsAcceptance {
    static void run() throws Exception {
        for (String input : new String[]{"https://secret.example/?token=secret", "host:443", "a\r\nHost: secret", " user.example", "-bad.example"}) {
            if (DiagnosticsDialog.validTarget(input)) throw new AssertionError("Unsafe diagnostic target accepted");
        }
        for (String input : new String[]{"example.com", "192.0.2.1", "2001:db8::1"}) {
            if (!DiagnosticsDialog.validTarget(input)) throw new AssertionError("Valid target rejected");
        }
        String response = "HTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Length: 99999999\r\n\r\n";
        if (DiagnosticsDialog.response(new ByteArrayInputStream(response.getBytes(StandardCharsets.US_ASCII))) != 403) throw new AssertionError("Final HTTP response lost");
        for (String input : new String[]{"HTTP/1.1 101 Switching\r\n\r\n", "HTTP/1.1 103 Early Hints\r\n\r\n", "HTTP/1.1 200 OK\r\nmalformed\r\n\r\n", "HTTP/1.1 200 OK\r\nX: " + "x".repeat(8192) + "\r\n\r\n"}) {
            try { DiagnosticsDialog.response(new ByteArrayInputStream(input.getBytes(StandardCharsets.US_ASCII))); }
            catch (IOException expected) { continue; }
            throw new AssertionError("Malformed or oversized headers accepted");
        }
        DiagnosticsDialog.Job job = new DiagnosticsDialog.Job(); job.cancel();
        java.net.Socket socket = new java.net.Socket();
        try { job.own(socket); throw new AssertionError("Cancelled job accepted socket"); }
        catch (IOException expected) { if (!socket.isClosed()) throw new AssertionError("Late socket not closed"); }
    }
}
