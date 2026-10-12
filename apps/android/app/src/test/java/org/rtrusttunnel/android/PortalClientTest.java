package org.rtrusttunnel.android;

import org.json.*;

/** Synthetic sequence regressions; run with an actual org.json runtime, no network/JNI/Keystore. */
public final class PortalClientTest {
    static void check(boolean value, String label) { if (!value) throw new AssertionError(label); }
    static JSONArray list(String json) throws Exception { return new JSONArray(json); }
    static final String TOKEN = "t".repeat(40), OTHER_TOKEN = "u".repeat(40);

    /** Mirrors ProfileVault: the encrypted file is read fresh, mutated by applyBatch, then written. */
    static final class SyntheticVault {
        String disk;
        SyntheticVault(String disk) { this.disk = disk; }
        void syncPortal(JSONObject session, JSONArray remote) throws Exception {
            JSONObject data = new JSONObject(disk);
            PortalClient.applyBatch(data, session, remote, false, 42L);
            disk = data.toString();
        }
        void syncPortalBackground(JSONObject session, JSONArray remote) throws Exception {
            JSONObject data = new JSONObject(disk);
            if (PortalClient.applyBatch(data, session, remote, true, 42L)) disk = data.toString();
        }
        JSONObject data() throws Exception { return new JSONObject(disk); }
    }
    static JSONObject session() throws Exception {
        return new JSONObject().put("origin", "https://fixture.invalid").put("token", TOKEN).put("background_sync", true);
    }
    /** Local profile, a stale managed profile and an expired-auth marker. */
    static SyntheticVault vault(String selected) throws Exception {
        JSONObject data = new JSONObject()
            .put("profiles", list("[{\"id\":\"local\",\"profile\":{\"name\":\"local\"}},"
                + "{\"id\":\"portal:old\",\"remote_id\":\"old\",\"revision\":\"r0\",\"profile\":{\"name\":\"old\"}}]"))
            .put("default", selected).put("portal", session().put("sync_auth_expired", true));
        return new SyntheticVault(data.toString());
    }

    static final class Fixture extends PortalClient {
        final JSONArray before, after;
        int lists, exports;
        boolean failRecheck, failFirstExport, failSecondExport, interruptRecheck, stopped;
        Runnable duringExport, stopAfterFirstExport;
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
            check(path.endsWith("/export"), "export path");
            check("r1".equals(body.getString("revision")), "export uses first-list revision");
            exports++;
            if (exports == 1 && failFirstExport) throw new java.io.IOException("Synthetic first export failure");
            if (exports == 2 && failSecondExport) throw new java.io.IOException("Synthetic mid-batch failure");
            if (exports == 1 && duringExport != null) duringExport.run();
            if (exports == 1 && stopAfterFirstExport != null) stopAfterFirstExport.run();
            return new JSONObject().put("content", "synthetic");
        }
        @Override JSONObject parseExport(String content) throws Exception { return new JSONObject().put("name", "synthetic"); }
    }

    static void rejectedDownload(JSONArray before, JSONArray after) throws Exception {
        Fixture fixture = new Fixture(before, after);
        String firstBytes = before.toString(), lastBytes = after.toString();
        try { fixture.download(); throw new AssertionError("Changed/malformed list accepted"); }
        catch (java.io.IOException | IllegalArgumentException | JSONException expected) { }
        check(before.toString().equals(firstBytes) && after.toString().equals(lastBytes), "metadata not mutated");
    }

    static void metadataSequences() throws Exception {
        JSONArray initial = list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"portal_managed\"},{\"id\":\"two\",\"revision\":\"r1\"}]");
        check(new Fixture(initial, initial).download().length() == 2, "stable snapshot");
        JSONArray reordered = list("[{\"id\":\"two\",\"revision\":\"r1\",\"origin\":null},{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"portal_managed\"}]");
        check(new Fixture(initial, reordered).download().length() == 2, "order independent, missing/null origin unknown");
        rejectedDownload(initial, list("[{\"id\":\"one\",\"revision\":\"r2\",\"origin\":\"portal_managed\"},{\"id\":\"two\",\"revision\":\"r1\"}]"));
        rejectedDownload(initial, list("[]"));
        rejectedDownload(initial, list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"portal_managed\"},{\"id\":\"two\",\"revision\":\"r1\"},{\"id\":\"three\",\"revision\":\"r1\"}]"));
        rejectedDownload(initial, list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":\"external_stored\"},{\"id\":\"two\",\"revision\":\"r1\"}]"));
        JSONArray duplicate = list("[{\"id\":\"one\",\"revision\":\"r1\"},{\"id\":\"one\",\"revision\":\"r1\"}]");
        rejectedDownload(initial, duplicate);
        Fixture badFirst = new Fixture(duplicate, initial);
        try { badFirst.download(); throw new AssertionError("Initial duplicate accepted"); } catch (java.io.IOException expected) { }
        check(badFirst.exports == 0, "duplicates rejected before downloads");
        for (String revision : new String[]{"", "has space", "line\n", "é", "x".repeat(257)}) {
            JSONArray malformed = new JSONArray().put(new JSONObject().put("id", "one").put("revision", revision));
            rejectedDownload(malformed, initial); rejectedDownload(initial, malformed);
        }
        rejectedDownload(initial, list("[{\"id\":\"one\",\"revision\":12}]"));
        check(new Fixture(list("[]"), list("[]")).download().length() == 0, "empty snapshot rechecked");
    }

    /** Shared with iOS ParityTests.testPortalOriginLabelPolicy: identical inputs and expectations. */
    static void originPolicy() throws Exception {
        String[] rejected = {"", "​", "portal​managed", "‮portal", "\u0085", "\u007F", "﻿portal",
            "line\n", "é", "x".repeat(81)};
        String[] accepted = {"portal_managed", "external_stored", "future source", "~", "x".repeat(80)};
        for (String origin : rejected) {
            check(!PortalClient.originLabel(origin), "origin rejected: " + (origin.isEmpty() ? "empty" : "U+" + Integer.toHexString(origin.codePointAt(0))));
            try {
                PortalClient.metadata(new JSONArray().put(new JSONObject().put("id", "one").put("revision", "r1").put("origin", origin)));
                throw new AssertionError("Invalid origin accepted in metadata");
            } catch (java.io.IOException expected) { }
        }
        for (String origin : accepted) {
            check(PortalClient.originLabel(origin), "origin accepted: " + origin);
            check(origin.equals(PortalClient.metadata(new JSONArray().put(new JSONObject().put("id", "one").put("revision", "r1")
                .put("origin", origin))).get("one").get(1)), "origin preserved");
        }
        try { PortalClient.metadata(list("[{\"id\":\"one\",\"revision\":\"r1\",\"origin\":12}]")); throw new AssertionError("Non-string origin"); }
        catch (java.io.IOException expected) { }
    }

    /** Download failure points: the vault keeps both managed and local profiles byte-for-byte. */
    static void failedSyncKeepsVault() throws Exception {
        JSONArray initial = list("[{\"id\":\"one\",\"revision\":\"r1\"},{\"id\":\"two\",\"revision\":\"r1\"}]");
        JSONArray rotated = list("[{\"id\":\"one\",\"revision\":\"r2\"},{\"id\":\"two\",\"revision\":\"r1\"}]");
        // 0 first export, 1 mid-batch export, 2 recheck I/O, 3 recheck changed, 4 interrupt, 5 worker stop.
        for (int mode = 0; mode < 6; mode++) {
            SyntheticVault vault = vault("portal:old");
            String original = vault.disk;
            Fixture fixture = new Fixture(initial, mode == 3 ? rotated : initial);
            fixture.failFirstExport = mode == 0;
            fixture.failSecondExport = mode == 1;
            fixture.failRecheck = mode == 2;
            fixture.interruptRecheck = mode == 4;
            if (mode == 5) fixture.stopAfterFirstExport = () -> fixture.stopped = true;
            try {
                vault.syncPortalBackground(session(), fixture.download(() -> fixture.stopped));
                throw new AssertionError("Failed batch committed, mode " + mode);
            } catch (java.io.IOException expected) {
                check(mode < 4 || expected instanceof java.io.InterruptedIOException, "cancellation surfaces as InterruptedIOException");
            } finally { Thread.interrupted(); }
            check(vault.disk.equals(original), "failed batch leaves vault unchanged, mode " + mode);
            JSONArray kept = vault.data().getJSONArray("profiles");
            check(kept.length() == 2 && kept.getJSONObject(0).getString("id").equals("local")
                && kept.getJSONObject(1).getString("id").equals("portal:old"), "managed and local retained");
            if (mode == 5) check(fixture.exports == 1 && fixture.lists == 1, "stop callback halts before next export and recheck");
        }
    }

    /** Registration replaced, disabled or removed while the batch was downloading. */
    static void registrationFence() throws Exception {
        JSONArray initial = list("[{\"id\":\"one\",\"revision\":\"r1\"}]");
        for (String change : new String[]{"token", "disabled", "removed"}) for (boolean background : new boolean[]{true, false}) {
            SyntheticVault vault = vault("local");
            Fixture fixture = new Fixture(initial, initial);
            fixture.duringExport = () -> {
                try {
                    JSONObject data = vault.data();
                    if (change.equals("token")) data.getJSONObject("portal").put("token", OTHER_TOKEN);
                    else if (change.equals("disabled")) data.getJSONObject("portal").put("background_sync", false);
                    else data.remove("portal");
                    vault.disk = data.toString();
                } catch (Exception failure) { throw new AssertionError(failure); }
            };
            JSONArray remote = fixture.download();
            String changed = vault.disk;
            // Foreground sync is user-initiated and ignores the background toggle (unchanged semantics).
            boolean commits = !background && change.equals("disabled");
            try {
                if (background) vault.syncPortalBackground(session(), remote); else vault.syncPortal(session(), remote);
                // Background fence rejects silently (no write); foreground must throw unless it commits.
                check(commits || background, "fence must reject " + change + (background ? " background" : " foreground"));
            } catch (java.io.IOException expected) {
                check(!background && !commits && "Registration changed".equals(expected.getMessage()), "foreground fence error");
            }
            if (!commits) {
                check(vault.disk.equals(changed), "stale batch not committed: " + change + (background ? " background" : " foreground"));
                check(vault.data().getJSONArray("profiles").getJSONObject(1).getString("id").equals("portal:old"), "old managed retained");
            }
        }
    }

    static void successfulApply() throws Exception {
        JSONArray initial = list("[{\"id\":\"two\",\"revision\":\"r1\"},{\"id\":\"one\",\"revision\":\"r1\"}]");
        // portal:two is not first after sync, so it stays selected only if the selection is kept.
        for (String selected : new String[]{"local", "portal:old", "portal:two"}) {
            SyntheticVault vault = vault(selected);
            String expected = selected.equals("portal:old") ? "local" : selected;
            vault.syncPortalBackground(session(), new Fixture(initial, initial).download());
            JSONObject data = vault.data();
            JSONArray profiles = data.getJSONArray("profiles");
            check(profiles.length() == 3 && profiles.getJSONObject(0).getString("id").equals("local")
                && profiles.getJSONObject(1).getString("id").equals("portal:one")
                && profiles.getJSONObject(2).getString("id").equals("portal:two"), "managed replaced, local kept");
            check(data.getString("default").equals(expected), "selection kept or repaired to first profile");
            check(data.getJSONObject("portal").getLong("last_sync") == 42L && !data.getJSONObject("portal").has("sync_auth_expired"), "sync marker");
        }
        // Rejections inside applyBatch never touch the caller's object.
        JSONObject data = vault("portal:old").data();
        String original = data.toString();
        JSONArray duplicate = list("[{\"id\":\"portal:x\",\"remote_id\":\"x\"},{\"id\":\"portal:x\",\"remote_id\":\"x\"}]");
        JSONArray oversized = new JSONArray();
        for (int i = 0; i < 64; i++) oversized.put(new JSONObject().put("id", "portal:p" + i).put("remote_id", "p" + i));
        for (JSONArray remote : new JSONArray[]{duplicate, oversized}) {
            try { PortalClient.applyBatch(data, session(), remote, false, 42L); throw new AssertionError("Invalid batch applied"); }
            catch (java.io.IOException expected) { }
            check(data.toString().equals(original), "rejected batch leaves data unchanged");
        }
    }

    public static void main(String[] args) throws Exception {
        metadataSequences();
        originPolicy();
        failedSyncKeepsVault();
        registrationFence();
        successfulApply();
        System.out.println("PASS Android synthetic whole-batch sync sequences");
    }
}
