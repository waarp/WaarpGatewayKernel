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
package org.waarp.gateway.kernel;

import java.util.HashMap;

import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.waarp.gateway.kernel.database.DbConstant;
import org.waarp.gateway.kernel.database.WaarpActionLogger;
import org.waarp.gateway.kernel.session.HttpSession;

/**
 * @author "Frederic Bregier"
 * 
 */
public class HttpPageHandler {
	/*
	 * Need as default error pages: 400, 401, 403, 404, 406, 500
	 */

	public static String hostid;

	public HashMap<String, HttpPage> hashmap;

	/**
	 * @param hashmap
	 */
	public HttpPageHandler(HashMap<String, HttpPage> hashmap) {
		this.hashmap = hashmap;
	}

	/**
	 * 
	 * @param code
	 * @return an HttpPage according to the error code (400, 404, 500, ...)
	 */
	public HttpPage getHttpPage(int code) {
		String scode = Integer.toString(code);
		return this.hashmap.get(scode);
	}

	/**
	 * 
	 * @param uri
	 * @param method
	 * @param session
	 * @return the associated HttpPage if any
	 * @throws HttpIncorrectRequestException
	 */
	public HttpPage getHttpPage(String uri, String method, HttpSession session)
			throws HttpIncorrectRequestException {
		HttpPage page = this.hashmap.get(uri);
		if (page == null) {
			return null;
		}
		switch (page.pagerole) {
			case DELETE:
				if (!method.equalsIgnoreCase("DELETE")) {
					// error
					WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
							"Incorrect Page: " + page.pagerole, HttpResponseStatus.BAD_REQUEST);
					if (page.errorpage != null || page.errorpage.length() > 1) {
						page = this.hashmap.get(page.errorpage);
					} else {
						page = null;
					}
				}
				break;
			case HTML:
			case MENU:
				// no check
				break;
			case GETDOWNLOAD:
				if (!method.equalsIgnoreCase("GET")) {
					// error
					WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
							"Incorrect Page: " + page.pagerole, HttpResponseStatus.BAD_REQUEST);
					if (page.errorpage != null || page.errorpage.length() > 1) {
						page = this.hashmap.get(page.errorpage);
					} else {
						page = null;
					}
				}
				break;
			case POST:
			case POSTUPLOAD:
				if (!method.equalsIgnoreCase("POST")) {
					// error
					WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
							"Incorrect Page: " + page.pagerole, HttpResponseStatus.BAD_REQUEST);
					if (page.errorpage != null || page.errorpage.length() > 1) {
						page = this.hashmap.get(page.errorpage);
					} else {
						page = null;
					}
				}
				break;
			case PUT:
				if (!method.equalsIgnoreCase("PUT")) {
					// error
					WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
							"Incorrect Page: " + page.pagerole, HttpResponseStatus.BAD_REQUEST);
					if (page.errorpage != null || page.errorpage.length() > 1) {
						page = this.hashmap.get(page.errorpage);
					} else {
						page = null;
					}
				}
				break;
			case ERROR:
				break;
			default:
				// error
				WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
						"Incorrect Page: " + page.pagerole, HttpResponseStatus.BAD_REQUEST);
				if (page.errorpage != null || page.errorpage.length() > 1) {
					page = this.hashmap.get(page.errorpage);
				} else {
					page = null;
				}
		}
		if (page == null) {
			throw new HttpIncorrectRequestException("No Page found");
		}
		return page;
	}
}
