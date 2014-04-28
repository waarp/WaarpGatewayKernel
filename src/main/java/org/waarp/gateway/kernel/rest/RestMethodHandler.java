/**
   This file is part of Waarp Project.

   Copyright 2009, Frederic Bregier, and individual contributors by the @author
   tags. See the COPYRIGHT.txt in the distribution for a full listing of
   individual contributors.

   All Waarp Project is free software: you can redistribute it and/or 
   modify it under the terms of the GNU General Public License as published 
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Waarp is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Waarp .  If not, see <http://www.gnu.org/licenses/>.
 */
package org.waarp.gateway.kernel.rest;

import java.util.HashSet;
import java.util.Set;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.multipart.FileUpload;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.exception.HttpForbiddenRequestException;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.exception.HttpInvalidAuthenticationException;
import org.waarp.gateway.kernel.exception.HttpMethodNotAllowedRequestException;
import org.waarp.gateway.kernel.exception.HttpNotFoundRequestException;
import org.waarp.gateway.kernel.rest.HttpRestHandler.METHOD;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author "Frederic Bregier"
 *
 */
public abstract class RestMethodHandler {
	protected final String path;
	protected final Set<METHOD> methods;
	protected final boolean isBodyJsonDecode;
	
	public RestMethodHandler(String path, boolean isBodyJsonDecode, METHOD ...method) {
		this.path = path;
		this.methods = new HashSet<HttpRestHandler.METHOD>();
		for (METHOD method2 : method) {
			methods.add(method2);
		}
		methods.add(METHOD.OPTIONS);
		this.isBodyJsonDecode = isBodyJsonDecode;
	}
	
	
	/**
	 * Check the session (arguments, result) vs handler correctness, called before any BODY elements but after URI and HEADER.
	 * 
	 * @param handler
	 * @param arguments
	 * @param result
	 * @throws HttpForbiddenRequestException
	 */
	public abstract void checkHandlerSessionCorrectness(HttpRestHandler handler, RestArgument arguments, RestArgument result) throws HttpForbiddenRequestException;

	/**
	 * Get a new Http Uploaded File from BODY
	 * @param handler
	 * @param data
	 * @param arguments
	 * @param result
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void getFileUpload(HttpRestHandler handler, FileUpload data, RestArgument arguments, RestArgument result) throws HttpIncorrectRequestException;

	/**
	 * Get data from BODY (supposedly a Json)
	 * @param handler
	 * @param body
	 * @param arguments
	 * @param result
	 * @return the object related to BODY decoding
	 * @throws HttpIncorrectRequestException
	 */
	public abstract Object getBody(HttpRestHandler handler, ChannelBuffer body, RestArgument arguments, RestArgument result) throws HttpIncorrectRequestException;
	
	/**
	 * Called when all Data were passed to the handler
	 * @param handler
	 * @param arguments
	 * @param result
	 * @param body
	 * @throws HttpIncorrectRequestException
	 * @throws HttpNotFoundRequestException 
	 */
	public abstract void endParsingRequest(HttpRestHandler handler, RestArgument arguments, RestArgument result, Object body) throws HttpIncorrectRequestException, HttpInvalidAuthenticationException, HttpNotFoundRequestException;
	
	/**
	 * Called when an exception occurs 
	 * @param handler
	 * @param arguments
	 * @param result
	 * @param body
	 * @param exception
	 * @return the status to used in sendReponse
	 */
	public HttpResponseStatus handleException(HttpRestHandler handler, RestArgument arguments, RestArgument result, Object body, Exception exception) {
		if (exception instanceof HttpInvalidAuthenticationException) {
			return HttpResponseStatus.UNAUTHORIZED;
		} else if (exception instanceof HttpForbiddenRequestException) {
			return HttpResponseStatus.FORBIDDEN;
		} else if (exception instanceof HttpIncorrectRequestException) {
			return HttpResponseStatus.BAD_REQUEST;
		} else if (exception instanceof HttpMethodNotAllowedRequestException) {
			return HttpResponseStatus.METHOD_NOT_ALLOWED;
		} else if (exception instanceof HttpNotFoundRequestException) {
			return HttpResponseStatus.NOT_FOUND;
		} else {
			return HttpResponseStatus.INTERNAL_SERVER_ERROR;
		}
	}

	/**
	 * Send a response (correct or not)
	 * @param handler
	 * @param channel
	 * @param arguments
	 * @param result
	 * @param body
	 * @param status
	 * @return The ChannelFuture if this response will need the channel to be closed, else null
	 */
	public abstract ChannelFuture sendResponse(HttpRestHandler handler, Channel channel, RestArgument arguments, RestArgument result, Object body, HttpResponseStatus status);

	protected ChannelFuture sendOptionsResponse(HttpRestHandler handler, Channel channel, RestArgument result, HttpResponseStatus status) {
		HttpResponse response = handler.getResponse();
		if (status == HttpResponseStatus.UNAUTHORIZED) {
			ChannelFuture future = channel.write(response);
			return future;
		}
		response.headers().add(HttpHeaders.Names.CONTENT_TYPE, "application/json");
		response.headers().add(HttpHeaders.Names.REFERER, handler.getRequest().getUri());
		String list = result.getItem(HttpHeaders.Names.ALLOW);
		response.headers().add(HttpHeaders.Names.ALLOW, list);
		String answer = result.toString();
		ChannelBuffer buffer = ChannelBuffers.wrappedBuffer(answer.getBytes(WaarpStringUtils.UTF8));
		response.headers().add(HttpHeaders.Names.CONTENT_LENGTH, buffer.readableBytes());
		response.setContent(buffer);
		ChannelFuture future = channel.write(response);
		if (handler.isWillClose()) {
			return future;
		}
		return future;
	}
	
	/**
	 * Options command that all handler should implement
	 * @param handler
	 * @param arguments
	 * @param result
	 */
	protected void optionsCommand(HttpRestHandler handler, RestArgument arguments, RestArgument result) {
		METHOD [] realmethods = METHOD.values();
		boolean []allMethods = new boolean[realmethods.length];
		for (METHOD methoditem : methods) {
			allMethods[methoditem.ordinal()] = true;
		}
		String allow = null;
		for (int i = 0; i < allMethods.length; i++) {
			if (allMethods[i]) {
				if (allow == null) {
					allow = realmethods[i].name();
				} else {
					allow += "," + realmethods[i].name();
				}
			}
		}
		result.addItem(HttpHeaders.Names.ALLOW, allow);
		allow = path;
		result.addItem(RestArgument.X_ALLOW_URIS, allow);
		ArrayNode array = getDetailedAllow();
		if (array != null) {
			ObjectNode node = result.getAnswer();
			node.putArray(RestArgument.X_DETAILED_ALLOW).addAll(array);
		}
	}
	/**
	 * 
	 * @return the detail of the method handler
	 */
	protected abstract ArrayNode getDetailedAllow();
	/**
	 * @return the isBodyJson
	 */
	public boolean isBodyJsonDecoded() {
		return isBodyJsonDecode;
	}
}
