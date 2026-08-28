package com.auditlog.verifier;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.auditlog.hashing.AuditEventHeader;
import com.auditlog.hashing.CommittedPayload;
import com.auditlog.hashing.EventHasher;
import com.auditlog.hashing.ExportBundle;
import com.auditlog.hashing.ExportBundleFormat;
import com.auditlog.hashing.ExportHasher;
import com.auditlog.hashing.ExportedRecord;
import com.auditlog.hashing.HashFormat;
import com.auditlog.hashing.Hex;
import com.auditlog.hashing.PayloadCommitter;
import com.fasterxml.jackson.databind.JsonNode;

class VerifierMainTest {

    @TempDir
    Path temp;

    @Test
    @DisplayName("an honest bundle file exits 0")
    void honestBundleExitsZero() throws Exception {
        Path file = write(temp.resolve("bundle.json"), honestRecord());

        Capture capture = capture(file.toString());

        assertThat(capture.code()).isZero();
        assertThat(capture.out()).contains("intact");
    }

    @Test
    @DisplayName("a tampered bundle file exits 1")
    void tamperedBundleExitsOne() throws Exception {
        ExportedRecord honest = honestRecord();
        ExportedRecord tampered = new ExportedRecord(
                honest.seq(),
                honest.header(),
                "{\"amount\":999}",
                honest.payloadRootHex(),
                honest.contentHashHex(),
                honest.previousChainHashHex(),
                honest.chainHashHex(),
                honest.hashVersion(),
                honest.archived(),
                honest.commitments());
        Path file = write(temp.resolve("bundle.json"), tampered);

        Capture capture = capture(file.toString());

        assertThat(capture.code()).isEqualTo(1);
        assertThat(capture.out()).contains("NOT INTACT");
    }

    @Test
    @DisplayName("missing arguments print usage and exit 2")
    void missingArgsExitTwo() {
        Capture capture = capture();

        assertThat(capture.code()).isEqualTo(2);
        assertThat(capture.err()).contains("usage:");
    }

    @Test
    @DisplayName("a missing file exits 2")
    void missingFileExitsTwo() {
        Capture capture = capture(temp.resolve("nope.json").toString());

        assertThat(capture.code()).isEqualTo(2);
        assertThat(capture.err()).contains("not a file");
    }

    @Test
    @DisplayName("malformed JSON exits 2")
    void malformedJsonExitsTwo() throws Exception {
        Path file = temp.resolve("bad.json");
        Files.writeString(file, "{");

        Capture capture = capture(file.toString());

        assertThat(capture.code()).isEqualTo(2);
        assertThat(capture.err()).contains("failed to verify");
    }

    @Test
    @DisplayName("null arguments print usage and exit 2")
    void nullArgsExitTwo() {
        Capture capture = captureRaw(null);

        assertThat(capture.code()).isEqualTo(2);
        assertThat(capture.err()).contains("usage:");
    }

    @Test
    @DisplayName("a directory is not a bundle file")
    void directoryExitsTwo() {
        Capture capture = capture(temp.toString());

        assertThat(capture.code()).isEqualTo(2);
        assertThat(capture.err()).contains("not a file");
    }

    @Test
    @DisplayName("JSON that is not a bundle exits 2")
    void invalidBundleShapeExitsTwo() throws Exception {
        Path file = temp.resolve("not-a-bundle.json");
        Files.writeString(file, "{\"hashVersion\":\"nope\"}");

        Capture capture = capture(file.toString());

        assertThat(capture.code()).isEqualTo(2);
        assertThat(capture.err()).contains("failed to verify");
    }

    @Test
    @DisplayName("main on an honest bundle returns without exiting the process")
    void mainOnHonestBundleDoesNotExit() throws Exception {
        Path file = write(temp.resolve("main-bundle.json"), honestRecord());

        VerifierMain.main(new String[] {file.toString()});
    }

    @Test
    @DisplayName("a failed verify invokes the failure exit with that code")
    void failedVerifyInvokesFailureExit() {
        AtomicInteger exited = new AtomicInteger(-1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();

        VerifierMain.runAndExit(
                new String[0],
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                exited::set);

        assertThat(exited.get()).isEqualTo(2);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("usage:");
    }

    @Test
    @DisplayName("an honest verify does not invoke the failure exit")
    void honestVerifyDoesNotInvokeFailureExit() throws Exception {
        Path file = write(temp.resolve("ok.json"), honestRecord());
        AtomicInteger exited = new AtomicInteger(-1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();

        VerifierMain.runAndExit(
                new String[] {file.toString()},
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                exited::set);

        assertThat(exited.get()).isEqualTo(-1);
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("intact");
    }

    private static Path write(Path file, ExportedRecord record) throws Exception {
        String manifest = Hex.encode(ExportHasher.manifestHash(HashFormat.VERSION, 1, 1, List.of(record.toLink())));
        Files.writeString(
                file,
                ExportBundleFormat.toJson(new ExportBundle(HashFormat.VERSION, 1, 1, manifest, List.of(record)))
                        .toString());
        return file;
    }

    private static ExportedRecord honestRecord() {
        JsonNode payload = com.auditlog.hashing.CanonicalJson.parse("{\"amount\":100}");
        CommittedPayload committed = new PayloadCommitter().commit(payload);
        AuditEventHeader header = new AuditEventHeader(
                UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                "account.updated",
                "user-1",
                "account",
                "acc-1",
                Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2026-01-01T00:00:01Z"));
        byte[] content = EventHasher.contentHash(header, Hex.decode(committed.payloadRootHex()));
        byte[] chain = EventHasher.chainHash(HashFormat.genesisChainHash(), content);
        return new ExportedRecord(
                1,
                header,
                com.auditlog.hashing.CanonicalJson.canonicalString(payload),
                committed.payloadRootHex(),
                Hex.encode(content),
                HashFormat.GENESIS_CHAIN_HASH,
                Hex.encode(chain),
                HashFormat.VERSION,
                false,
                committed.fields());
    }

    private static Capture capture(String... args) {
        return captureRaw(args);
    }

    private static Capture captureRaw(String[] args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = VerifierMain.run(
                args,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        return new Capture(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private record Capture(int code, String out, String err) {}
}
