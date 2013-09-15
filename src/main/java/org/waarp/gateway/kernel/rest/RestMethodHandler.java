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

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.multipart.FileUpload;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.rest.HttpRestHandler.METHOD;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author "Frederic Bregier"
 *
 */
public abstract class RestMethodHandler {
	protected final String path;
	protected final METHOD []methods;
	protected final boolean isBodyDedicatedDecode;
	
	public RestMethodHandler(String path, boolean isBodyDedicatedDecode, METHOD ...method) {
		this.path = path;
		this.methods = method;
		this.isBodyDedicatedDecode = isBodyDedicatedDecode;
	}
	
	
	/**
	 * Check the arguments correctness, called before any BODY elements but after URI and HEADER.
	 * Note that ARG_METHOD is only set from current request. It might be also set from URI or HEADER 
	 * and therefore should be done in this method through 
	 * @param handler
	 * @param uri
	 * @param arguments
	 * @param result
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void checkArgumentsCorrectness(HttpRestHandler handler, String uri, ObjectNode arguments, ObjectNode result) throws HttpIncorrectRequestException;

	/**
	 * Get a new Http Uploaded File from BODY
	 * @param handler
	 * @param data
	 * @param arguments
	 * @param result
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void getFileUpload(HttpRestHandler handler, FileUpload data, ObjectNode arguments, ObjectNode result) throws HttpIncorrectRequestException;

	/**
	 * Get data from BODY
	 * @param handler
	 * @param body
	 * @param arguments
	 * @param result
	 * @return the object related to BODY decoding
	 * @throws HttpIncorrectRequestException
	 */
	public abstract Object getBody(HttpRestHandler handler, ChannelBuffer body, ObjectNode arguments, ObjectNode result) throws HttpIncorrectRequestException;
	
	/**
	 * Called when all Data were passed to getData
	 * @param handler
	 * @param arguments
	 * @param result
	 * @param body
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void endBody(HttpRestHandler handler, ObjectNode arguments, ObjectNode result, Object body) throws HttpIncorrectRequestException;
	
	/**
	 * Called when an exception occurs 
	 * @param handler
	 * @param arguments
	 * @param result
	 * @param body
	 * @param exception
	 * @return the status to used in sendReponse
	 * @throws Exception re-throw it if this exception is not handled
	 */
	public abstract HttpResponseStatus handleException(HttpRestHandler handler, ObjectNode arguments, ObjectNode result, Object body, Exception exception) throws Exception;

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
	public abstract ChannelFuture sendResponse(HttpRestHandler handler, Channel channel, ObjectNode arguments, ObjectNode result, Object body, HttpResponseStatus status);

	/**
	 * @return the isBodyJson
	 */
	public boolean isBodyDedicatedDecode() {
		return isBodyDedicatedDecode;
	}
}
