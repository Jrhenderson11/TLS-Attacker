/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.extension.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class ECPointFormatExtensionMessage extends ExtensionMessage {

    private List<ECPointFormat> pointFormatsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableVariable<Integer> pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableVariable<byte[]> pointFormats;

    public ECPointFormatExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.EC_POINT_FORMATS;
    }

    public ModifiableVariable<byte[]> getPointFormats() {
	return pointFormats;
    }

    public void setPointFormats(byte[] array) {
	if (this.pointFormats == null) {
	    this.pointFormats = new ModifiableVariable<>();
	}
	this.pointFormats.setOriginalValue(array);
    }

    public ModifiableVariable<Integer> getPointFormatsLength() {
	return pointFormatsLength;
    }

    public void setPointFormatsLength(int length) {
	if (this.pointFormatsLength == null) {
	    this.pointFormatsLength = new ModifiableVariable<>();
	}
	this.pointFormatsLength.setOriginalValue(length);
    }

    public void setPointFormatsLength(ModifiableVariable<Integer> pointFormatsLength) {
	this.pointFormatsLength = pointFormatsLength;
    }

    public void setPointFormats(ModifiableVariable<byte[]> pointFormats) {
	this.pointFormats = pointFormats;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return ECPointFormatExtensionHandler.getInstance();
    }

    public List<ECPointFormat> getPointFormatsConfig() {
	return pointFormatsConfig;
    }

    public void setPointFormatsConfig(List<ECPointFormat> pointFormatsConfig) {
	this.pointFormatsConfig = pointFormatsConfig;
    }

}
