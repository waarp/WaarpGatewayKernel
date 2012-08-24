/**
 * Copyright 2009, Frederic Bregier, and individual contributors by the @author tags. See the
 * COPYRIGHT.txt in the distribution for a full listing of individual contributors.
 * 
 * This is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either version 3.0 of the
 * License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with this
 * software; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.waarp.gateway.kernel.database;

import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.waarp.common.database.DbSession;
import org.waarp.common.database.data.AbstractDbData.UpdatedInfo;
import org.waarp.common.database.exception.WaarpDatabaseException;
import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;
import org.waarp.gateway.kernel.HttpPage.PageRole;
import org.waarp.gateway.kernel.database.data.DbTransferLog;
import org.waarp.gateway.kernel.session.HttpSession;

/**
 * Class to help to log any actions through the interface of Waarp
 * 
 * @author Frederic Bregier
 * 
 */
public class WaarpActionLogger {
	/**
	 * Internal Logger
	 */
	private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
			.getLogger(WaarpActionLogger.class);

	/**
	 * Log the action
	 * 
	 * @param httpSession
	 * @param message
	 * @param session
	 */
	public static void logCreate(DbSession httpSession,
			String message, HttpSession session) {
		String sessionContexte = session.toString();
		logger.info(message + " " + sessionContexte);
		if (httpSession != null) {
			PageRole code = session.getCurrentCommand();
			boolean isSender = false;
			switch (code) {
				case ERROR:
				case HTML:
				case MENU:
					session.setLogid(DbConstant.ILLEGALVALUE);
					return;
				case DELETE:
				case GETDOWNLOAD:
					isSender = false;
					break;
				case POST:
				case POSTUPLOAD:
				case PUT:
					isSender = true;
					break;
				default:
					break;
			}
			// Insert new one
			try {
				DbTransferLog log =
						new DbTransferLog(httpSession,
								session.getAuth().getUser(),
								session.getAuth().getAccount(),
								DbConstant.ILLEGALVALUE,
								isSender, session.getFilename(),
								code.name(),
								HttpResponseStatus.OK, message,
								UpdatedInfo.TOSUBMIT);
				logger.debug("Create FS: " + log.toString());
				session.setLogid(log.getSpecialId());
				return;
			} catch (WaarpDatabaseException e1) {
				// Do nothing
			}
			/*
			 * if (FileBasedConfiguration.fileBasedConfiguration.monitoring != null) { if (isSender)
			 * { FileBasedConfiguration.fileBasedConfiguration.monitoring .updateLastOutBand(); }
			 * else { FileBasedConfiguration.fileBasedConfiguration.monitoring .updateLastInBound();
			 * } }
			 */
		}
		session.setLogid(DbConstant.ILLEGALVALUE);
	}

	/**
	 * Log the action
	 * 
	 * @param httpSession
	 * @param session
	 * @param message
	 * @param rcode
	 * @param info
	 */
	public static void logAction(DbSession httpSession,
			HttpSession session, String message, HttpResponseStatus rcode,
			UpdatedInfo info) {
		String sessionContexte = session.toString();
		long specialId = session.getLogid();
		logger.info(message + " " + sessionContexte);
		if (httpSession != null && specialId != DbConstant.ILLEGALVALUE) {
			PageRole code = session.getCurrentCommand();
			switch (code) {
				case ERROR:
				case HTML:
				case MENU:
					return;
				case DELETE:
				case GETDOWNLOAD:
				case POST:
				case POSTUPLOAD:
				case PUT:
					break;
				default:
					return;
			}
			try {
				// Try load
				DbTransferLog log =
						new DbTransferLog(httpSession,
								session.getAuth().getUser(),
								session.getAuth().getAccount(), specialId);
				log.changeUpdatedInfo(info);
				log.setInfotransf(message);
				log.setReplyCodeExecutionStatus(rcode);
				log.update();
				logger.debug("Update FS: " + log.toString());
				session.setLogid(log.getSpecialId());
				return;
			} catch (WaarpDatabaseException e) {
				// Do nothing
			}
		}
	}

	/**
	 * Log the action in error
	 * 
	 * @param ftpSession
	 * @param session
	 * @param message
	 * @param rcode
	 */
	public static void logErrorAction(DbSession ftpSession,
			HttpSession session,
			String message, HttpResponseStatus rcode) {
		String sessionContexte = session.toString();
		long specialId = session.getLogid();
		logger.error(rcode.getCode() + ":" + message + " " + sessionContexte);
		logger.warn("To Change to debug Log",
				new Exception("Log"));
		if (ftpSession != null && specialId != DbConstant.ILLEGALVALUE) {
			PageRole code = session.getCurrentCommand();
			switch (code) {
				case ERROR:
				case HTML:
				case MENU:
					return;
				case DELETE:
				case GETDOWNLOAD:
				case POST:
				case POSTUPLOAD:
				case PUT:
					break;
				default:
					return;
			}
			UpdatedInfo info = UpdatedInfo.INERROR;
			try {
				// Try load
				DbTransferLog log =
						new DbTransferLog(ftpSession,
								session.getAuth().getUser(),
								session.getAuth().getAccount(), specialId);
				log.changeUpdatedInfo(info);
				log.setInfotransf(message);
				if (rcode.getCode() < 400) {
					log.setReplyCodeExecutionStatus(HttpResponseStatus.BAD_REQUEST);
				} else {
					log.setReplyCodeExecutionStatus(rcode);
				}
				if (session.getFilename() != null) {
					log.setFilename(session.getFilename());
				}
				log.update();
				logger.debug("Update FS: " + log.toString());
			} catch (WaarpDatabaseException e) {
				// Do nothing
			}
		}
	}
}
