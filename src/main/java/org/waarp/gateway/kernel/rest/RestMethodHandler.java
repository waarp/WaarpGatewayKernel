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

import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.exception.HttpIncorrectRetrieveException;
import org.waarp.gateway.kernel.rest.HttpRestHandler.METHOD;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * @author "Frederic Bregier"
 *
 */
public abstract class RestMethodHandler {
	protected final String path;
	protected final METHOD []methods;
	
	public RestMethodHandler(String path, METHOD ...method) {
		this.path = path;
		this.methods = method;
	}
	
	/**
	 * Check the arguments correctness
	 * @param arguments
	 * @param result
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void checkArgumentsCorrectness(JsonNode arguments, JsonNode result) throws HttpIncorrectRequestException;

	/**
	 * Get a new Http data from BODY
	 * @param data
	 * @param arguments
	 * @param result
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void getData(InterfaceHttpData data, JsonNode arguments, JsonNode result) throws HttpIncorrectRequestException;
	
	/**
	 * Called when all Data were passed to getData
	 * @param arguments
	 * @param result
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void endBody(JsonNode arguments, JsonNode result) throws HttpIncorrectRequestException;
	
	/**
	 * Called when an exception occurs 
	 * @param arguments
	 * @param result
	 * @param exception
	 * @return the status to used in sendReponse
	 * @throws Exception re-throw it if this exception is not handled
	 */
	public abstract HttpResponseStatus handleException(JsonNode arguments, JsonNode result, Exception exception) throws Exception;

	/**
	 * Send a response (correct or not)
	 * @param channel
	 * @param arguments
	 * @param result
	 * @param status
	 * @return True if this response will need the channel to be closed
	 * @throws HttpIncorrectRequestException
	 * @throws HttpIncorrectRetrieveException
	 */
	public abstract boolean sendResponse(Channel channel, JsonNode arguments, JsonNode result, HttpResponseStatus status) throws HttpIncorrectRequestException, HttpIncorrectRetrieveException;
}
