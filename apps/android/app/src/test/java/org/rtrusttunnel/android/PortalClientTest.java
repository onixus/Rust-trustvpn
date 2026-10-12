package org.rtrusttunnel.android;

import org.json.*;

/** Synthetic sequence regressions; run with an actual org.json runtime, no network/vault. */
public final class PortalClientTest {
    static void check(boolean value, String label) { if (!value) throw new AssertionError(label); }
    static JSONArray list(String json) throws Exception { return new JSONArray(json); }
    static final class Fixture extends PortalClient {
        final JSONArray before, after;
        int lists, exports;
        boolean failRecheck, cancelExport, interruptRecheck;
        Fixture(JSONArray before, JSONArray after) throws Exception {
            super("https://fixture.invalid", ""); this.before = before; this.after = after;
        }
        @Override JSONObject request(String path, JSONObject body) throws Exception {
            if (path.equals("/portal/v2/profiles")) {
                lists++;
                if (lists == 2 && interruptRecheck) Thread.currentThread().interrupt();
                if (lists == 2 && failRecheck) throw new java.io.IOException("Synthetic recheck failure");
                return new JSONObject().put("profiles", lists == 1 ? before : after);
            }
            if (cancelExport) throw new java.io.InterruptedIOException("Synthetic cancellation");
            check(path.endsWith("/export"), "export path");
            check("r1".equals(body.getString("revision")), "export uses first-list revision");
            exports++;
            return new JSONObject().put("content", "synthetic");
        }
        @Override JSONObject parseExport(String content) throws Exception { return new JSONObject().put("name", "synthetic"); }
    }
    static void rejected(JSONArray before, JSONArray after) throws Exception {
        Fixture fixture = new Fixture(before, after);
        String firstBytes = before.toString(), lastBytes = after.toString();
        JSONArray retainedLocal = list("[{\"id\":\"local\"}]");
        String retained = retainedLocal.toString();
        try { retainedLocal = fixture.download(); throw new AssertionError("Changed/malformed list accepted"); }
        catch (java.io.IOException | IllegalArgumentException | JSONException expected) { }
        check(retainedLocal.toString().equals(retained), "failed download publishes no partial replacement");
        check(before.toString().equals(firstBytes) && after.toString().equals(lastBytes), "metadata not mutated");
    }
    public static void main(String[] args) throws Exception {
        JSONArray initial = list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"portal_managed\"},{\"id\":\"two\",\"revision\":\"r1\"}]");
        check(new Fixture(initial, initial).download().length() == 2, "stable snapshot");
        JSONArray reordered = list("[{\"id\":\"two\",\"revision\":\"r1\",\"origin\":null},{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"portal_managed\"}]");
        check(new Fixture(initial, reordered).download().length() == 2, "order independent, missing/null origin unknown");
        rejected(initial, list("[{\"id\":\"one\",\"revision\":\"r2\",\"origin\":\"portal_managed\"},{\"id\":\"two\",\"revision\":\"r1\"}]"));
        rejected(initial, list("[]"));
        rejected(initial, list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"portal_managed\"},{\"id\":\"two\",\"revision\":\"r1\"},{\"id\":\"three\",\"revision\":\"r1\"}]"));
        rejected(initial, list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"external_stored\"},{\"id\":\"two\",\"revision\":\"r1\"}]"));
        JSONArray duplicate = list("[{\"id\":\"one\",\"revision\":\"r1\"},{\"id\":\"one\",\"revision\":\"r1\"}]");
        rejected(initial, duplicate);
        Fixture badFirst = new Fixture(duplicate, initial);
        try { badFirst.download(); throw new AssertionError("Initial duplicate accepted"); } catch (java.io.IOException expected) { }
        check(badFirst.exports == 0, "duplicates rejected before downloads");
        for (String revision : new String[]{"", "has space", "line\n", "é", "x".repeat(257)}) {
            JSONArray malformed = new JSONArray().put(new JSONObject().put("id", "one").put("revision", revision));
            rejected(malformed, initial); rejected(initial, malformed);
        }
        rejected(initial, list("[{\"id\":\"one\",\"revision\":12}]"));
        check(new Fixture(list("[]"), list("[]")).download().length() == 0, "empty snapshot rechecked");
        for (boolean cancel : new boolean[]{false, true}) {
            Fixture failing = new Fixture(initial, initial);
            failing.failRecheck = !cancel; failing.cancelExport = cancel;
            JSONArray local = list("[{\"id\":\"local\"}]");
            try { local = failing.download(); throw new AssertionError("Interrupted/failed batch accepted"); }
            catch (java.io.IOException expected) { }
            check(local.getJSONObject(0).getString("id").equals("local"), "failed batch leaves caller state intact");
        }
        Fixture interrupted = new Fixture(initial, initial);
        interrupted.interruptRecheck = true;
        try { interrupted.download(); throw new AssertionError("Cancelled result published"); }
        catch (java.io.InterruptedIOException expected) { }
        finally { Thread.interrupted(); }
        System.out.println("PASS Android synthetic whole-batch sync sequences");
    }
}
