/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerHelloHandler extends HandshakeMessageHandler<ServerHelloMessage> {

    public ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerHelloMessagePreparator getPreparator(ServerHelloMessage message) {
        return new ServerHelloMessagePreparator(tlsContext, message);
    }

    @Override
    public ServerHelloMessageSerializer getSerializer(ServerHelloMessage message) {
        return new ServerHelloMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    public ServerHelloParser getParser(byte[] message, int pointer) {
        return new ServerHelloParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    protected void adjustTLSContext(ServerHelloMessage message) {
        adjustSelectedCiphersuite(message);
        adjustSelectedCompression(message);
        adjustSelectedProtocolVersion(message);
        adjustSelectedSessionID(message);
        adjustServerRandom(message);
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                extension.getHandler(tlsContext).adjustTLSContext(extension);
            }
        }
        adjustMessageDigest(message);
    }

    private void adjustSelectedCiphersuite(ServerHelloMessage message) {
        CipherSuite suite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        tlsContext.setSelectedCipherSuite(suite);
        LOGGER.debug("Set SelectedCipherSuite in Context to " + suite.name());
    }

    private void adjustServerRandom(ServerHelloMessage message) {
        byte[] random = ArrayConverter.concatenate(message.getUnixTime().getValue(), message.getRandom().getValue());
        tlsContext.setServerRandom(random);
        LOGGER.debug("Set ServerRandom in Context to " + ArrayConverter.bytesToHexString(random));
    }

    private void adjustSelectedCompression(ServerHelloMessage message) {
        CompressionMethod method = CompressionMethod.getCompressionMethod(message.getSelectedCompressionMethod()
                .getValue());
        tlsContext.setSelectedCompressionMethod(method);
        LOGGER.debug("Set SelectedCompressionMethod in Context to " + method.name());
    }

    private void adjustSelectedSessionID(ServerHelloMessage message) {
        byte[] sessionID = message.getSessionId().getValue();
        tlsContext.setSessionID(sessionID);
        LOGGER.debug("Set SessionID in Context to " + ArrayConverter.bytesToHexString(sessionID, false));

    }

    private void adjustSelectedProtocolVersion(ServerHelloMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        tlsContext.setSelectedProtocolVersion(version);
        LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
    }

    private void adjustMessageDigest(ServerHelloMessage message) {
        tlsContext.initiliazeTlsMessageDigest();
        LOGGER.debug("Initializing TLS Message Digest");
    }
}