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
package org.waarp.gateway.kernel.session;

import org.waarp.gateway.kernel.HttpPage.PageRole;

/**
 * @author Frederic Bregier
 * 
 */
public class HttpSession extends RestSession {
	private String cookieSession;
	private PageRole currentCommand;
	protected String filename;

	/**
	 */
	public HttpSession() {
	}

	/**
	 * @return the currentCommand
	 */
	public PageRole getCurrentCommand() {
		return currentCommand;
	}

	/**
	 * @param currentCommand
	 *            the currentCommand to set
	 */
	public void setCurrentCommand(PageRole currentCommand) {
		this.currentCommand = currentCommand;
	}

	/**
	 * @return the cookieSession
	 */
	public String getCookieSession() {
		return cookieSession;
	}

	/**
	 * @param cookieSession
	 *            the cookieSession to set
	 */
	public void setCookieSession(String cookieSession) {
		this.cookieSession = cookieSession;
	}

	/**
	 * @return the filename
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * @param filename
	 *            the filename to set
	 */
	public void setFilename(String filename) {
		this.filename = filename;
	}


	public String toString() {
		return "Command: " + currentCommand.name() + " Filename: " + filename;
	}
}
