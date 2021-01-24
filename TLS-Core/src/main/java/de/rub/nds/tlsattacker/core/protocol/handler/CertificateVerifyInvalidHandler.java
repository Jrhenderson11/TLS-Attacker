/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyInvalidMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateVerifyInvalidPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateVerifySerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handling of the CertificateVerify protocol message:
 * http://tools.ietf.org/html/rfc5246#section-7.4.8
 *
 * The TLS spec as well as wireshark bring some nice confusions: - The TLS spec
 * says the message consists of only signature bytes - Wireshark says the
 * message consists of the signature length and signature bytes
 *
 * In fact, the certificate message consists of the following fields: -
 * signature algorithm (2 bytes) - signature length (2 bytes) - signature
 *
 * This structure is of course prepended with the handshake message length, as
 * obvious for every handshake message.
 */
public class CertificateVerifyInvalidHandler extends HandshakeMessageHandler<CertificateVerifyInvalidMessage> {

    public CertificateVerifyInvalidHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateVerifyParser getParser(byte[] message, int pointer) {
        return new CertificateVerifyParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                tlsContext.getConfig());
    }

    @Override
    public CertificateVerifyInvalidPreparator getPreparator(CertificateVerifyInvalidMessage message) {
        return new CertificateVerifyInvalidPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public CertificateVerifySerializer getSerializer(CertificateVerifyInvalidMessage message) {
        return new CertificateVerifySerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(CertificateVerifyInvalidMessage message) {
        // Maybe check if we can verify signature and set boolean in context
        // //TODO
        // Dont adjust the TLSContext
    }
}
