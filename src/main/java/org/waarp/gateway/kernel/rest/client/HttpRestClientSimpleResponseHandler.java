/*
 * Copyright 2009 Red Hat, Inc.
 * 
 * Red Hat licenses this file to you under the Apache License, version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.waarp.gateway.kernel.rest.client;

import java.net.ConnectException;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.UnsupportedCharsetException;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.waarp.common.crypto.ssl.WaarpSslUtility;
import org.waarp.common.json.JsonHandler;
import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.rest.RestArgument;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * 
 * @author Frederic Bregier
 */
public class HttpRestClientSimpleResponseHandler extends SimpleChannelUpstreamHandler {
	/**
     * Internal Logger
     */
    private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
            .getLogger(HttpRestClientSimpleResponseHandler.class);
    
    private volatile boolean readingChunks;
    private ChannelBuffer cumulativeBody = null;
    protected JsonNode jsonObject = null;
    
    protected void addContent(HttpResponse response) throws HttpIncorrectRequestException {
    	ChannelBuffer content = response.getContent();
        if (content != null && content.readable()) {
            if (cumulativeBody != null) {
				cumulativeBody = ChannelBuffers.wrappedBuffer(cumulativeBody, content);
			} else {
				cumulativeBody = content;
			}
            // get the Json equivalent of the Body
    		try {
    			String json = cumulativeBody.toString(WaarpStringUtils.UTF8);
    			jsonObject = JsonHandler.getFromString(json);
    		} catch (UnsupportedCharsetException e2) {
    			logger.warn("Error", e2);
    			throw new HttpIncorrectRequestException(e2);
    		}
			cumulativeBody = null;
        }
    }
    
    protected void actionFromResponse(Channel channel) {
    	RestArgument ra = new RestArgument((ObjectNode) jsonObject);
    	if (jsonObject == null) {
    		logger.warn("Recv: EMPTY");
    	} else {
    		logger.warn(ra.prettyPrint());
    	}
    	((RestFuture) channel.getAttachment()).setRestArgument(ra);
    	if (ra.getStatusCode() == HttpResponseStatus.OK.getCode()) {
    		((RestFuture) channel.getAttachment()).setSuccess();
    	} else {
            logger.error("Error: "+ra.getStatusMessage());
    		((RestFuture) channel.getAttachment()).cancel();
            if (channel.isConnected()) {
            	WaarpSslUtility.closingSslChannel(channel);
            }
    	}
    }
    
    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e)
            throws Exception {
        Object obj = e.getMessage();
        if (!readingChunks && (obj instanceof HttpResponse)) {
            HttpResponse response = (HttpResponse) e.getMessage();
            HttpResponseStatus status = response.getStatus();
            logger.debug(HttpHeaders.Names.REFERER+": "+response.headers().get(HttpHeaders.Names.REFERER) +
                    " STATUS: " + status);

            if (response.getStatus().getCode() == 200 && response.isChunked()) {
                readingChunks = true;
            } else {
                addContent(response);
                actionFromResponse(e.getChannel());
            }
        } else {
            readingChunks = true;
            HttpChunk chunk = (HttpChunk) e.getMessage();
            if (chunk.isLast()) {
                readingChunks = false;
                ChannelBuffer content = chunk.getContent();
                if (content != null && content.readable()) {
                    if (cumulativeBody != null) {
        				cumulativeBody = ChannelBuffers.wrappedBuffer(cumulativeBody, content);
        			} else {
        				cumulativeBody = content;
        			}
                }
                // get the Json equivalent of the Body
                if (cumulativeBody == null) {
                	jsonObject = JsonHandler.createObjectNode();
                } else {
	        		try {
	        			String json = cumulativeBody.toString(WaarpStringUtils.UTF8);
	        			jsonObject = JsonHandler.getFromString(json);
	        		} catch (Throwable e2) {
	        			logger.warn("Error", e2);
	        			throw new HttpIncorrectRequestException(e2);
	        		}
	    			cumulativeBody = null;
                }                
                actionFromResponse(e.getChannel());
            } else {
            	ChannelBuffer content = chunk.getContent();
                if (content != null && content.readable()) {
                    if (cumulativeBody != null) {
        				cumulativeBody = ChannelBuffers.wrappedBuffer(cumulativeBody, content);
        			} else {
        				cumulativeBody = content;
        			}
                }
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e)
            throws Exception {
        if (e.getCause() instanceof ClosedChannelException) {
        	((RestFuture) e.getChannel().getAttachment()).setFailure(e.getCause());
        	logger.debug("Close before ending");
            return;
        } else if (e.getCause() instanceof ConnectException) {
        	((RestFuture) e.getChannel().getAttachment()).setFailure(e.getCause());
            if (ctx.getChannel().isConnected()) {
            	logger.debug("Will close");
            	WaarpSslUtility.closingSslChannel(e.getChannel());
            }
            return;
        }
    	((RestFuture) e.getChannel().getAttachment()).setFailure(e.getCause());
    	logger.error("Error", e.getCause());
        WaarpSslUtility.closingSslChannel(e.getChannel());
    }

}
