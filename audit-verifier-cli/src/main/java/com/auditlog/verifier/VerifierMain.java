package com.auditlog.verifier;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.IntConsumer;

import com.auditlog.hashing.BundleVerifier;
import com.auditlog.hashing.ExportBundle;
import com.auditlog.hashing.ExportBundleFormat;
import com.auditlog.hashing.HashFormat;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Offline verifier for an exported bundle. Depends on the hashing core only — never on the live
 * service or its database.
 *
 * <p>Usage: {@code java -jar audit-verifier.jar bundle.json}
 */
public final class VerifierMain {

    private VerifierMain() {}

    public static void main(String[] args) {
        runAndExit(args, System.out, System.err, System::exit);
    }

    static void runAndExit(String[] args, PrintStream out, PrintStream err, IntConsumer onFailure) {
        int code = run(args, out, err);
        if (code != 0) {
            onFailure.accept(code);
        }
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        out.println("audit-verifier (hash format v" + HashFormat.VERSION + ")");
        if (args == null || args.length != 1) {
            err.println("usage: audit-verifier <bundle.json>");
            return 2;
        }
        Path path = Path.of(args[0]);
        if (!Files.isRegularFile(path)) {
            err.println("failed to verify: not a file: " + path);
            return 2;
        }
        try {
            ExportBundle bundle = ExportBundleFormat.fromJson(new ObjectMapper().readTree(path.toFile()));
            BundleVerifier.Result result = new BundleVerifier().verify(bundle);
            if (result.intact()) {
                out.println("intact: sequences %d-%d, %d record(s)"
                        .formatted(result.fromSeq(), result.toSeq(), result.recordsChecked()));
                out.println("manifest " + result.manifestHashHex());
                return 0;
            }
            out.println("NOT INTACT");
            for (BundleVerifier.Check check : result.checks()) {
                out.println("%d %s %s".formatted(check.seq(), check.type(), check.detail()));
            }
            return 1;
        } catch (IOException e) {
            err.println("failed to verify: " + e.getMessage());
            return 2;
        } catch (RuntimeException e) {
            err.println("failed to verify: " + e.getMessage());
            return 2;
        }
    }
}
