/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CertificateVerifiyConstants;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.SSLUtils;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyInvalidMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Random;

public class CertificateVerifyInvalidPreparator extends HandshakeMessagePreparator<CertificateVerifyInvalidMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private SignatureAndHashAlgorithm algorithm;
    private byte[] signature;
    private final CertificateVerifyInvalidMessage msg;

    public CertificateVerifyInvalidPreparator(Chooser chooser, CertificateVerifyInvalidMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateVerifiyMessage");
        algorithm = chooser.getSelectedSigHashAlgorithm();
        signature = new byte[0];
        try {
            signature = createSignature();
        } catch (CryptoException E) {
            LOGGER.warn("Could not generate Signature! Using empty one instead!", E);
        }
        prepareSignature(msg);
        prepareSignatureLength(msg);
        prepareSignatureHashAlgorithm(msg);
    }

    private byte[] createSignature() throws CryptoException {

        byte[] b = new byte[512];
        new Random().nextBytes(b);

        return b;
    }

    private void prepareSignature(CertificateVerifyInvalidMessage msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    private void prepareSignatureLength(CertificateVerifyInvalidMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void prepareSignatureHashAlgorithm(CertificateVerifyInvalidMessage msg) {
        msg.setSignatureHashAlgorithm(algorithm.getByteValue());
        LOGGER.debug("SignatureHasAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureHashAlgorithm().getValue()));
    }
}
