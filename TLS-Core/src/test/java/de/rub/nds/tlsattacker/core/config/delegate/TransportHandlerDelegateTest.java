/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.TransportHandlerDelegate;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TransportHandlerDelegateTest {

    private TransportHandlerDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public TransportHandlerDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new TransportHandlerDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getTransportHandlerType method, of class
     * TransportHandlerDelegate.
     */
    @Test
    public void testGetTransportHandlerType() {
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "UDP";
        assertFalse(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
        jcommander.parse(args);
        assertTrue(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidTransportHandlerType() {
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "NOTATRANSPORTHANDLER";
        jcommander.parse(args);
    }

    /**
     * Test of setTransportHandlerType method, of class
     * TransportHandlerDelegate.
     */
    @Test
    public void testSetTransportHandlerType() {
        assertFalse(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
        delegate.setTransportHandlerType(TransportHandlerType.UDP);
        assertTrue(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
    }

    /**
     * Test of applyDelegate method, of class TransportHandlerDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "UDP";
        jcommander.parse(args);
        config.setTransportHandlerType(TransportHandlerType.TCP);
        assertFalse(config.getTransportHandlerType() == TransportHandlerType.UDP);
        delegate.applyDelegate(config);
        assertTrue(config.getTransportHandlerType() == TransportHandlerType.UDP);
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }

}