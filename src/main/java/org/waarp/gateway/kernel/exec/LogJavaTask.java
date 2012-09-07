/**
 * This file is part of Waarp Project.
 * 
 * Copyright 2009, Frederic Bregier, and individual contributors by the @author tags. See the
 * COPYRIGHT.txt in the distribution for a full listing of individual contributors.
 * 
 * All Waarp Project is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * Waarp is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with Waarp . If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.waarp.gateway.kernel.exec;

import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;

/**
 * @author "Frederic Bregier"
 * 
 */
public class LogJavaTask implements GatewayRunnable {
	/**
	 * Internal Logger
	 */
	private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
			.getLogger(LogJavaTask.class);

	boolean waitForValidation;
	boolean useLocalExec;
	int delay;
	String[] args;

	/**
	 * 
	 */
	public LogJavaTask() {
	}

	@Override
	public void run() {
		StringBuilder builder = new StringBuilder();
		for (String arg : args) {
			builder.append(arg);
			builder.append(' ');
		}
		switch (delay) {
			case 0:
				logger.warn(builder.toString());
				break;
			case 1:
				logger.debug(builder.toString());
				break;
			case 2:
				logger.info(builder.toString());
				break;
			case 3:
				logger.warn(builder.toString());
				break;
			case 4:
				logger.error(builder.toString());
				break;
			default:
				logger.warn(builder.toString());
				break;
		}
	}

	@Override
	public void setArgs(boolean waitForValidation, boolean useLocalExec, int delay, String[] args) {
		this.waitForValidation = waitForValidation;
		this.useLocalExec = useLocalExec;
		this.delay = delay;
		this.args = args;
	}

	@Override
	public int getFinalStatus() {
		return 0;
	}

}
