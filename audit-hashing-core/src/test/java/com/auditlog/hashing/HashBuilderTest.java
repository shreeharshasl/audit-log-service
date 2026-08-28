package com.auditlog.hashing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mockStatic;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class HashBuilderTest {

    @Test
    @DisplayName("length framing makes concatenation unambiguous")
    void framingPreventsBoundaryCollisions() {
        byte[] first =
                HashBuilder.withTag(DomainTag.CONTENT).field("ab").field("c").build();
        byte[] second =
                HashBuilder.withTag(DomainTag.CONTENT).field("a").field("bc").build();

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    @DisplayName("the same fields under different domain tags hash differently")
    void domainTagsSeparateHashSpaces() {
        byte[] asContent = HashBuilder.withTag(DomainTag.CONTENT).field("x").build();
        byte[] asChain = HashBuilder.withTag(DomainTag.CHAIN).field("x").build();

        assertThat(asContent).isNotEqualTo(asChain);
    }

    @Test
    @DisplayName("null is distinguishable from the empty string")
    void nullIsNotEmpty() {
        byte[] nullField =
                HashBuilder.withTag(DomainTag.CONTENT).field((String) null).build();
        byte[] emptyField = HashBuilder.withTag(DomainTag.CONTENT).field("").build();

        assertThat(nullField).isNotEqualTo(emptyField);
    }

    @Test
    @DisplayName("identical input produces identical output")
    void isDeterministic() {
        byte[] first = HashBuilder.withTag(DomainTag.CONTENT)
                .int32(7)
                .field("value")
                .int64(99L)
                .build();
        byte[] second = HashBuilder.withTag(DomainTag.CONTENT)
                .int32(7)
                .field("value")
                .int64(99L)
                .build();

        assertThat(first).isEqualTo(second).hasSize(32);
    }

    @Test
    @DisplayName("a platform without SHA-256 fails visibly rather than producing a weaker digest")
    void missingSha256IsFatal() {
        try (MockedStatic<MessageDigest> digest = mockStatic(MessageDigest.class)) {
            digest.when(() -> MessageDigest.getInstance("SHA-256")).thenThrow(new NoSuchAlgorithmException("missing"));

            assertThatThrownBy(HashBuilder::newDigest)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("SHA-256")
                    .hasCauseInstanceOf(NoSuchAlgorithmException.class);
        }
    }
}
