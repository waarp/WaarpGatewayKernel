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

import org.waarp.common.command.exception.CommandAbstractException;
import org.waarp.common.file.DirInterface;
import org.waarp.common.file.FileParameterInterface;
import org.waarp.common.file.Restart;
import org.waarp.common.file.SessionInterface;
import org.waarp.common.file.filesystembased.FilesystemBasedOptsMLSxImpl;
import org.waarp.gateway.kernel.HttpPage.PageRole;
import org.waarp.gateway.kernel.commonfile.CommonDirImpl;
import org.waarp.gateway.kernel.commonfile.FilesystemBasedFileParameterImpl;
import org.waarp.gateway.kernel.database.DbConstant;

/**
 * @author Frederic Bregier
 * 
 */
public class HttpSession implements SessionInterface {
	private HttpAuthInterface httpAuth;
	private String cookieSession;
	private PageRole currentCommand;
	private long logid = DbConstant.ILLEGALVALUE;
	private String filename;
	private CommonDirImpl dir;

	/**
	 */
	public HttpSession() {
	}

	/**
	 * @param httpAuth
	 *            the httpAuth to set
	 */
	public void setHttpAuth(HttpAuthInterface httpAuth) {
		this.httpAuth = httpAuth;
		dir = new CommonDirImpl(this, new FilesystemBasedOptsMLSxImpl());
		try {
			dir.changeDirectoryNotChecked(httpAuth.getUser());
			dir.changeDirectoryNotChecked(httpAuth.getAccount());
		} catch (CommandAbstractException e) {
		}
	}

	@Override
	public DirInterface getDir() {
		return dir;
	}

	@Override
	public HttpAuthInterface getAuth() {
		return this.httpAuth;
	}

	@Override
	public void clear() {
		if (httpAuth != null) {
			httpAuth.clear();
		}
	}

	@Override
	public int getBlockSize() {
		return 8192; // HttpChunk size
	}

	@Override
	public FileParameterInterface getFileParameter() {
		return FilesystemBasedFileParameterImpl.fileParameterInterface;
	}

	@Override
	public Restart getRestart() {
		return null;
	}

	@Override
	public String getUniqueExtension() {
		return ".postu";
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
	 * @return the logid
	 */
	public long getLogid() {
		return logid;
	}

	/**
	 * @param logid
	 *            the logid to set
	 */
	public void setLogid(long logid) {
		this.logid = logid;
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
