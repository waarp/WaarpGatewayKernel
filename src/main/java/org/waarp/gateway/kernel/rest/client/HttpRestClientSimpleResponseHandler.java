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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;

import org.waarp.common.crypto.ssl.WaarpSslUtility;
import org.waarp.common.json.JsonHandler;
import org.waarp.common.logging.WaarpLogger;
import org.waarp.common.logging.WaarpLoggerFactory;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.rest.RestArgument;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * 
 * @author Frederic Bregier
 */
public class HttpRestClientSimpleResponseHandler extends SimpleChannelInboundHandler<Object> {
	/**
     * Internal Logger
     */
    private static final WaarpLogger logger = WaarpLoggerFactory
            .getLogger(HttpRestClientSimpleResponseHandler.class);
    
    private volatile boolean readingChunks;
    private ByteBuf cumulativeBody = null;
    protected JsonNode jsonObject = null;
    
    protected void addContent(HttpResponse response) throws HttpIncorrectRequestException {
    	ByteBuf content = response.getContent();
        if (content != null && content.isReadable()) {
            if (cumulativeBody != null) {
				cumulativeBody = Unpooled.wrappedBuffer(cumulativeBody, content);
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
    	if (ra.getStatusCode() == HttpResponseStatus.OK.code()) {
    		((RestFuture) channel.getAttachment()).setSuccess();
    	} else {
            logger.error("Error: "+ra.getStatusMessage());
    		((RestFuture) channel.getAttachment()).cancel();
            if (channel.isActive()) {
            	WaarpSslUtility.closingSslChannel(channel);
            }
    	}
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!readingChunks && (msg instanceof HttpResponse)) {
            HttpResponse response = (HttpResponse) msg;
            HttpResponseStatus status = response.status();
            logger.debug(HttpHeaders.Names.REFERER+": "+response.headers().get(HttpHeaders.Names.REFERER) +
                    " STATUS: " + status);

            if (response.status().code() == 200 && HttpHeaders.isTransferEncodingChunked(response)) {
                readingChunks = true;
            } else {
                addContent(response);
                actionFromResponse(e.channel());
            }
        } else {
            readingChunks = true;
            HttpChunk chunk = (HttpChunk) msg;
            if (chunk.isLast()) {
                readingChunks = false;
                ByteBuf content = chunk.getContent();
                if (content != null && content.isReadable()) {
                    if (cumulativeBody != null) {
        				cumulativeBody = Unpooled.wrappedBuffer(cumulativeBody, content);
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
                actionFromResponse(ctx.channel());
            } else {
            	ByteBuf content = chunk.getContent();
                if (content != null && content.isReadable()) {
                    if (cumulativeBody != null) {
        				cumulativeBody = Unpooled.wrappedBuffer(cumulativeBody, content);
        			} else {
        				cumulativeBody = content;
        			}
                }
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
            throws Exception {
        if (cause instanceof ClosedChannelException) {
        	((RestFuture) ctx.channel().getAttachment()).setFailure(cause);
        	logger.debug("Close before ending");
            return;
        } else if (cause instanceof ConnectException) {
        	((RestFuture) ctx.channel().getAttachment()).setFailure(cause);
            if (ctx.channel().isActive()) {
            	logger.debug("Will close");
            	WaarpSslUtility.closingSslChannel(e.channel());
            }
            return;
        }
    	((RestFuture) ctx.channel().getAttachment()).setFailure(cause);
    	logger.error("Error", cause);
        WaarpSslUtility.closingSslChannel(ctx.channel());
    }

}
