/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MitmDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.TimeoutDelegate;

public class TokenBindingMitmCommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "token_binding_mitm";

    // @Parameter(names = "-certificate", description =
    // "Path to a certificate file in PEM format. "
    // +
    // "This is the 'faked' certificate that the MitM presents to the client as server "
    // + "certifcate.")
    // private String serverCertPath;

    @Parameter(names = "-chrome", description = "Set this if using chrome. Allows to handle multiple requests.")
    private Boolean chrome = false;

    @ParametersDelegate
    private MitmDelegate mitmDelegate;
    @ParametersDelegate
    private TimeoutDelegate timeoutDelegate;

    public TokenBindingMitmCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        mitmDelegate = new MitmDelegate();
        addDelegate(mitmDelegate);
        timeoutDelegate = new TimeoutDelegate();
        addDelegate(timeoutDelegate);
    }

    // public String getServerCertPath() {
    // return serverCertPath;
    // }
    //
    // public void setServerCertPath(String serverCertPath) {
    // this.serverCertPath = serverCertPath;
    // }

    public Boolean isChrome() {
        return chrome;
    }

    public void setChrome(Boolean chrome) {
        this.chrome = chrome;
    }

    /*
     * Always execute attack.
     */
    @Override
    public boolean isExecuteAttack() {
        return true;
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        return config;
    }
}
