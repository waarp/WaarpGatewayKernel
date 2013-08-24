/**
 * This file is part of Waarp Project (named also Waarp or GG).
 * 
 * Copyright 2009, Frederic Bregier, and individual contributors by the @author
 * tags. See the COPYRIGHT.txt in the distribution for a full listing of
 * individual contributors.
 * 
 * All Waarp Project is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * Waarp is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * Waarp . If not, see <http://www.gnu.org/licenses/>.
 */
package org.waarp.gateway.kernel.rest;

import org.waarp.common.crypto.ssl.WaarpSslUtility;
import org.waarp.common.json.JsonHandler;
import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.HttpBusinessFactory;
import org.waarp.gateway.kernel.database.DbConstant;
import org.waarp.gateway.kernel.database.WaarpActionLogger;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.exception.HttpInvalidAuthenticationException;
import org.waarp.gateway.kernel.session.RestSession;

import java.nio.channels.ClosedChannelException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.handler.codec.http.Cookie;
import org.jboss.netty.handler.codec.http.CookieDecoder;
import org.jboss.netty.handler.codec.http.CookieEncoder;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.jboss.netty.handler.codec.http.multipart.Attribute;
import org.jboss.netty.handler.codec.http.multipart.DefaultHttpDataFactory;
import org.jboss.netty.handler.codec.http.multipart.DiskAttribute;
import org.jboss.netty.handler.codec.http.multipart.DiskFileUpload;
import org.jboss.netty.handler.codec.http.multipart.FileUpload;
import org.jboss.netty.handler.codec.http.multipart.HttpDataFactory;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.EndOfDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.ErrorDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.IncompatibleDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.NotEnoughDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Handler for HTTP Rest support
 * 
 * @author Frederic Bregier
 * 
 */
public abstract class HttpRestHandler extends SimpleChannelUpstreamHandler {
	
	/**
	 * arguments.path(ARGS_HEADER) main entry for HEADER arguments
	 */
	public static final String ARGS_HEADER = "header";
	/**
	 * arguments.path(ARGS_COOKIE) main entry for COOKIE arguments
	 */
	public static final String ARGS_COOKIE = "cookie";
	/**
	 * arguments.path(ARGS_URI) main entry for URI arguments
	 */
	public static final String ARGS_URI = "uri";
	/**
	 * arguments.path(ARGS_BODY) main entry for BODY arguments
	 */
	public static final String ARGS_BODY = "body";
	/**
	 * arguments.path(ARG_PATH) = uri path
	 */
	public static final String ARG_PATH = "path";
	/**
	 * arguments.path(ARG_BASEPATH).asText() = uri base path
	 */
	public static final String ARG_BASEPATH = "base";
	/**
	 * arguments.path(ARGS_SUBPATH) main entry for SUB-PATH arguments<br>
	 * arguments.path(ARGS_SUBPATH).elements() for an iterator or .get(x) for xth SUB-PATH argument
	 */
	public static final String ARGS_SUBPATH = "subpath";
	/**
	 * arguments.path(ARG_METHOD).asText() = method identified
	 */
	public static final String ARG_METHOD = "X-method";
	/**
	 * arguments.path(ARG_HASBODY).asBoolean() = true if the body has content
	 */
	public static final String ARG_HASBODY = "hasBody";

	/**
     * Internal Logger
     */
    private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
            .getLogger(HttpRestHandler.class);
    
    /*
     * Note:
     * Presence de BODY dans toutes les requetes/responses = Content-Length ou Transfer-Encoding
     * 
     * OPTIONS: request + Content-Type ; response : si pas de body => Content-Length = 0
     * 
     * HEAD: response pas de BODY
     * 
     */
    
    public static enum METHOD {
    	/**
    	 * REST: Standard GET item
    	 * 
    	 * The GET method means retrieve whatever information (in the form of an entity) 
    	 * is identified by the Request-URI. If the Request-URI refers to a 
    	 * data-producing process, it is the produced data which shall be returned as 
    	 * the entity in the response and not the source text of the process, unless 
    	 * that text happens to be the output of the process.
    	 */
    	GET(HttpMethod.GET),
    	/**
    	 * REST: Update existing item
    	 * 
    	 * The PUT method requests that the enclosed entity be stored under the 
    	 * supplied Request-URI.
    	 */
    	PUT(HttpMethod.PUT),
    	/**
    	 * REST: Create a new item
    	 * 
    	 * The POST method is used to request that the origin server accept the 
    	 * entity enclosed in the request as a new subordinate of the resource 
    	 * identified by the Request-URI in the Request-Line.
    	 */
    	POST(HttpMethod.POST), 
    	/**
    	 * REST: Delete existing item
    	 * 
    	 * The DELETE method requests that the origin server delete the resource 
    	 * identified by the Request-URI.
    	 */
    	DELETE(HttpMethod.DELETE), 
    	/**
    	 * REST: what options are supported for the URI
    	 * 
    	 * The OPTIONS method represents a request for information about 
    	 * the communication options available on the request/response chain 
    	 * identified by the Request-URI. This method allows the client to 
    	 * determine the options and/or requirements associated with a resource, 
    	 * or the capabilities of a server, without implying a resource action 
    	 * or initiating a resource retrieval.
    	 */
    	OPTIONS(HttpMethod.OPTIONS), 
    	/**
    	 * REST: as GET but no BODY (existence ? metadata ?)
    	 * 
    	 * The HEAD method is identical to GET except that the server MUST NOT 
    	 * return a message-body in the response.
    	 */
    	HEAD(HttpMethod.HEAD),
    	/**
    	 * REST: should not be used, use POST instead
    	 * 
    	 * The PATCH method requests that a set of changes described in the 
    	 * request entity be applied to the resource identified by the Request-URI.
    	 */
    	PATCH(HttpMethod.PATCH),
    	/**
    	 * REST: unknown usage
    	 * 
    	 * The TRACE method is used to invoke a remote, application-layer 
    	 * loop-back of the request message.
    	 */
    	TRACE(HttpMethod.TRACE),
    	/**
    	 * REST: unknown
    	 * 
    	 * This specification reserves the method name CONNECT for use with 
    	 * a proxy that can dynamically switch to being a tunnel
    	 */
    	CONNECT(HttpMethod.CONNECT);
    	
    	public final HttpMethod method;
    	private METHOD(HttpMethod method) {
    		this.method = method;
    	}
    }
    
    public static final HttpDataFactory factory = new DefaultHttpDataFactory(
			DefaultHttpDataFactory.MINSIZE); 
    // Disk if size exceed MINSIZE = 16K
	// Disk if size exceed MINSIZE = 16K, but for FileUpload from Ark directly
	// XXX FIXME TODO to setup outside !
	public static String TempPath = "J:/GG/ARK/TMP"; // "C:/Temp/Java/GG/ARK/TMP";

	public static ChannelGroup group = null;
	
	public static HashMap<String, RestMethodHandler> restHashMap = 
			new HashMap<String, RestMethodHandler>();
	
	/**
	 * Initialize the Disk support
	 */
	public static void initialize(String tempPath) {
		TempPath = tempPath;
		DiskFileUpload.deleteOnExitTemporaryFile = true; // should delete file
															// on exit (in normal
															// exit)
		DiskFileUpload.baseDirectory = TempPath; // system temp
													// directory
		DiskAttribute.deleteOnExitTemporaryFile = true; // should delete file on
														// exit (in normal exit)
		DiskAttribute.baseDirectory = TempPath; // system temp directory
	}

    protected RestSession session = null;
	protected HttpPostRequestDecoder decoder = null;
	protected HttpResponseStatus status = HttpResponseStatus.OK;

	protected volatile HttpRequest request = null;
	protected volatile RestMethodHandler handler = null;
	
	protected volatile boolean willClose = false;

	protected volatile boolean readingChunks = false;

	/**
	 * Structure is:<br>
	 * ARG_PATH, ARG_BASEPATH, ARGS_SUBPATH (array), ARG_METHOD, ARG_HASBODY, 
	 * ARGS_URI (subset),
	 * ARGS_HEADER (subset),
	 * ARGS_COOKIE (subset),
	 * ARGS_BODY (subset)
	 * 
	 */
	protected volatile ObjectNode arguments = null;
	/**
	 * The only structure that might be needed is: ARGS_COOKIE (subset)
	 */
	protected volatile ObjectNode response = null;
	
	protected static class HttpCleanChannelFutureListener implements ChannelFutureListener {
		protected final HttpRestHandler handler;

		/**
		 * @param handler
		 */
		public HttpCleanChannelFutureListener(HttpRestHandler handler) {
			this.handler = handler;
		}

		@Override
		public void operationComplete(ChannelFuture future) throws Exception {
			handler.clean();
		}
	}

	/**
	 * To be used for instance to check correctness of connection<br>
	 * <br>
	 * for instance, if X-AUTH is included<br>
	 * check if in uri or header, X-AUTH is present and check X-AUTH argument (known, any key if present)<br>
	 * then get timestamp and check is correct (|curtime - timestamp| < maxinterval)<br>
	 * then get all uri args in alphabetic lower case order<br>
	 * hash using SHA-1 all args (in order including timestamp)<br>
	 * compare sha-1 hashedkey with the computed one
	 * 
	 * @param channel
	 * @throws HttpInvalidAuthenticationException
	 */
    protected abstract void checkConnection(Channel channel) throws HttpInvalidAuthenticationException;

    @Override
    public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e)
            throws Exception {
        if (group != null) {
            group.add(e.getChannel());
        }
		super.channelConnected(ctx, e);
    }
	
	/**
	 * Clean method
	 * 
	 * Override if needed
	 */
	protected void clean() {
		if (arguments != null) {
			arguments.removeAll();
			arguments = null;
		}
		if (response != null) {
			response.removeAll();
			response = null;
		}
		if (decoder != null) {
			decoder.cleanFiles();
			decoder = null;
		}
		if (session != null) {
			session.setLogid(DbConstant.ILLEGALVALUE);
		}
	}

	/**
	 * Called at the beginning of every new request
	 * 
	 * Override if needed
	 */
	protected void initialize() {
		// clean previous FileUpload if Any
		clean();
        if (session == null) {
        	session = new RestSession();
        }
		status = HttpResponseStatus.OK;
		request = null;
		willClose = false;
		readingChunks = false;
		arguments = JsonHandler.createObjectNode();
		response = JsonHandler.createObjectNode();
	}

	/**
	 * set values from URI into arguments.path(ARGS_URI)
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void getUriArgs() throws HttpIncorrectRequestException {
		QueryStringDecoder decoderQuery = new QueryStringDecoder(
				request.getUri());
		arguments.put(ARG_METHOD, request.getMethod().getName());
		String path = decoderQuery.getPath();
		arguments.put(ARG_PATH, path);
		// compute path main uri
		String basepath = path;
		int pos = basepath.indexOf('/');
		if (pos >= 0) {
			if (pos == 0) {
				int pos2 = basepath.indexOf('/', 1);
				if (pos2 < 0) {
					basepath = basepath.substring(1);
				} else {
					basepath = basepath.substring(1, pos2);
				}
			} else {
				basepath = basepath.substring(0, pos);
			}
		}
		arguments.put(ARG_BASEPATH, basepath);
		// compute sub path args
		if (pos == 0) {
			pos = path.indexOf('/', 1);
		}
		if (pos >= 0) {
			int pos2 = path.indexOf('/', pos+1);
			if (pos2 > 0) {
				ArrayNode array = arguments.putArray(ARGS_SUBPATH);
				while (pos2 > 0) {
					array.add(path.substring(pos+1, pos2));
					pos = pos2;
					pos2 = path.indexOf('/', pos+1);
				}
			}
		}
		arguments.putPOJO(ARGS_URI, decoderQuery.getParameters());
	}


	/**
	 * set values from Header into arguments.path(ARGS_HEADER)
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void getHeaderArgs() throws HttpIncorrectRequestException {
		arguments.putPOJO(ARGS_HEADER, request.getHeaders());
	}

	/**
	 * set values from Cookies into arguments.path(ARGS_COOKIE)
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void getCookieArgs() throws HttpIncorrectRequestException {
		Set<Cookie> cookies;
		String value = request.getHeader(HttpHeaders.Names.COOKIE);
		if (value == null) {
			cookies = Collections.emptySet();
		} else {
			CookieDecoder decoder = new CookieDecoder();
			cookies = decoder.decode(value);
		}
		if (!cookies.isEmpty()) {
			ObjectNode node = arguments.putObject(ARGS_COOKIE);
			for (Cookie cookie : cookies) {
				node.put(cookie.getName(), cookie.getValue());
			}
		}
	}
	
	/**
	 * Method to set Cookies in httpResponse from response ObjectNode
	 * 
	 * @param httpResponse
	 */
	protected void setCookies(HttpResponse httpResponse) {
		JsonNode cookieON = response.path(ARGS_COOKIE);
		if (! cookieON.isMissingNode()) {
			CookieEncoder cookieEncoder = new CookieEncoder(true);
			Iterator<Entry<String, JsonNode>> iter = cookieON.fields();
			while (iter.hasNext()) {
				Entry<String, JsonNode> entry = iter.next();
				cookieEncoder.addCookie(entry.getKey(), entry.getValue().asText());
			}
			httpResponse.addHeader(HttpHeaders.Names.SET_COOKIE, cookieEncoder.encode());
		}
	}


	/**
	 * Example of method to get method From URI
	 */
	public static void methodFromUri(ObjectNode arguments) {
		JsonNode node = arguments.path(ARGS_URI).path(ARG_METHOD);
		if (! node.isMissingNode()) {
			// override
			arguments.put(ARG_METHOD, node.asText());
		}
	}

	/**
	 * Example of method to get method From Header
	 */
	public static void methodFromHeader(ObjectNode arguments) {
		JsonNode node = arguments.path(ARGS_HEADER).path(ARG_METHOD);
		if (! node.isMissingNode()) {
			// override
			arguments.put(ARG_METHOD, node.asText());
		}
	}

	/**
	 * 
	 * @return the base path uri or empty String
	 */
	protected String getBASEURI() {
		return arguments.path(ARG_BASEPATH).asText();
	}

	/**
	 * 
	 * @return the uri or empty String
	 */
	protected String getURI() {
		return arguments.path(ARG_PATH).asText();
	}

	/**
	 * 
	 * @return the method or null
	 */
	protected METHOD getMethod() {
		String text = arguments.path(ARG_METHOD).asText();
		if (text == null || text.isEmpty()) {
			return null;
		}
		return METHOD.valueOf(text);
	}
	
	/**
	 * 
	 * @return RestMethodHandler associated with the current context
	 * @throws HttpIncorrectRequestException 
	 */
	protected RestMethodHandler getHandler() throws HttpIncorrectRequestException {
		METHOD method = getMethod();
		String uri = getBASEURI();
		WaarpActionLogger.logCreate(DbConstant.admin.session, "Request received: "
				+ arguments, session, uri+":"+method);
		boolean restFound = false;
		RestMethodHandler handler = restHashMap.get(uri);
		if (handler != null) {
			response = JsonHandler.createObjectNode();
			handler.checkArgumentsCorrectness(this, getURI(), arguments, response);
			for (METHOD meth : handler.methods) {
				if (meth == method) {
					restFound = true;
					break;
				}
			}
		}
		if (! restFound){
			throw new HttpIncorrectRequestException("No Method found for that URI: "+uri);
		}
		return handler;
	}

	@Override
	public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws HttpInvalidAuthenticationException {
		Channel channel = ctx.getChannel();
		try {
			if (!readingChunks) {
				initialize();
				this.request = (HttpRequest) e.getMessage();
				arguments.put(ARG_HASBODY, 
						(request.isChunked() || request.getContent() != ChannelBuffers.EMPTY_BUFFER));
				getUriArgs();
				getHeaderArgs();
				getCookieArgs();
				checkConnection(channel);
				handler = getHandler();
				
				if (request.isChunked()) {
					// no body yet
					readingChunks = true;
					createDecoder();
					return;
				} else {
					// decoder for 1 chunk
					createDecoder();
					// Not chunk version
					readAllHttpData();
					handler.endBody(this, arguments, response);
					handler.sendResponse(this, channel, arguments, response, status);
					return;
				}
			} else {
				// New chunk is received
				bodyChunk(e);
			}
		} catch (HttpIncorrectRequestException e1) {
			// real error => 400
			if (handler != null) {
				try {
					status = handler.handleException(this, arguments, response, e1);
				} catch (Exception e2) {
				}
			}
			if (status == HttpResponseStatus.OK) {
				status = HttpResponseStatus.BAD_REQUEST;
			}
			logger.warn("Error", e1);
			handler.sendResponse(this, channel, arguments, response, status);
		}
	}
	
	/**
	 * Create the decoder
	 * @throws HttpIncorrectRequestException
	 */
	protected void createDecoder() throws HttpIncorrectRequestException {
		HttpMethod method = request.getMethod();
        if (!method.equals(HttpMethod.HEAD)) {
        	// FIXME in order decoder allows to parse
            request.setMethod(HttpMethod.POST);
        }
		try {
			decoder = new HttpPostRequestDecoder(HttpBusinessFactory.factory, request);
		} catch (ErrorDataDecoderException e1) {
			status = HttpResponseStatus.NOT_ACCEPTABLE;
			throw new HttpIncorrectRequestException(e1);
		} catch (IncompatibleDataDecoderException e1) {
			// GETDOWNLOAD Method: should not try to create a HttpPostRequestDecoder
			// So OK but stop here
			status = HttpResponseStatus.NOT_ACCEPTABLE;
			throw new HttpIncorrectRequestException(e1);
		}
	}

	/**
	 * Read all InterfaceHttpData from finished transfer
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void readAllHttpData() throws HttpIncorrectRequestException {
		List<InterfaceHttpData> datas = null;
		try {
			datas = decoder.getBodyHttpDatas();
		} catch (NotEnoughDataDecoderException e1) {
			// Should not be!
			logger.warn("decoder issue", e1);
			status = HttpResponseStatus.NOT_ACCEPTABLE;
			throw new HttpIncorrectRequestException(e1);
		}
		for (InterfaceHttpData data : datas) {
			readHttpData(data);
		}
	}
	
	/**
	 * Read one Data
	 * 
	 * @param data
	 * @throws HttpIncorrectRequestException
	 */
	protected void readHttpData(InterfaceHttpData data)
			throws HttpIncorrectRequestException {
		if (data.getHttpDataType() == HttpDataType.Attribute) {
			Attribute attribute = (Attribute) data;
			handler.getData(this, attribute, arguments, response);
		} else if (data.getHttpDataType() == HttpDataType.FileUpload) {
			FileUpload fileUpload = (FileUpload) data;
			if (fileUpload.isCompleted()) {
				handler.getData(this, fileUpload, arguments, response);
			} else {
				logger.warn("File still pending but should not");
				fileUpload.delete();
				status = HttpResponseStatus.INTERNAL_SERVER_ERROR;
				throw new HttpIncorrectRequestException("File still pending but should not");
			}
		} else {
			logger.warn("Unknown element: " + data.toString());
		}
	}


	/**
	 * To allow quick answer even if in very bad shape
	 * 
	 * @param channel
	 */
	protected void forceClosing(Channel channel) {
		if (status == HttpResponseStatus.OK) {
			status = HttpResponseStatus.INTERNAL_SERVER_ERROR;
		}
		if (channel.isConnected()) {
			willClose = true;
			HttpResponse response = getResponse();
			response.setHeader(HttpHeaders.Names.CONTENT_TYPE, "text/html");
			response.setHeader(HttpHeaders.Names.REFERER, request.getUri());
			String answer = "<html><body>Error " + status.getReasonPhrase() + "</body></html>";
			response.setContent(ChannelBuffers.wrappedBuffer(answer.getBytes(WaarpStringUtils.UTF8)));
			ChannelFuture future = channel.write(response);
			logger.debug("Will close");
			future.addListener(WaarpSslUtility.SSLCLOSE);
		}
		WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
				"Error: " , status);
	}


	/**
	 * 
	 * @return the Http Response according to the status
	 */
	protected HttpResponse getResponse() {
		// Decide whether to close the connection or not.
		if (request == null) {
			HttpResponse response = new DefaultHttpResponse(
					HttpVersion.HTTP_1_0, status);
			setCookies(response);
			willClose = true;
			return response;
		}
		boolean keepAlive = HttpHeaders.isKeepAlive(request);
		willClose = willClose ||
				status != HttpResponseStatus.OK ||
				HttpHeaders.Values.CLOSE.equalsIgnoreCase(request
						.getHeader(HttpHeaders.Names.CONNECTION)) ||
				request.getProtocolVersion().equals(HttpVersion.HTTP_1_0) &&
				!keepAlive;
		if (willClose) {
			keepAlive = false;
		}
		// Build the response object.
		HttpResponse response = new DefaultHttpResponse(
				request.getProtocolVersion(), status);
		if (keepAlive) {
			response.setHeader(HttpHeaders.Names.CONNECTION,
					HttpHeaders.Values.KEEP_ALIVE);
		}
		setCookies(response);
		return response;
	}

	/**
	 * Method that get a chunk of data
	 * 
	 * @param e
	 * @throws HttpIncorrectRequestException
	 */
	protected void bodyChunk(MessageEvent e) throws HttpIncorrectRequestException {
		// New chunk is received: only for Post!
		HttpChunk chunk = (HttpChunk) e.getMessage();
		try {
			decoder.offer(chunk);
		} catch (ErrorDataDecoderException e1) {
			status = HttpResponseStatus.NOT_ACCEPTABLE;
			throw new HttpIncorrectRequestException(e1);
		}
		// example of reading chunk by chunk (minimize memory usage due to
		// Factory)
		readHttpDataChunkByChunk();
		// example of reading only if at the end
		if (chunk.isLast()) {
			readingChunks = false;
			handler.endBody(this, arguments, response);
			handler.sendResponse(this, e.getChannel(), arguments, response, status);
			clean();
		}
	}

	/**
	 * Read request by chunk and getting values from chunk to chunk
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void readHttpDataChunkByChunk() throws HttpIncorrectRequestException {
		try {
			while (decoder.hasNext()) {
				InterfaceHttpData data = decoder.next();
				if (data != null) {
					// new value
					readHttpData(data);
				}
			}
		} catch (EndOfDataDecoderException e1) {
			// end
			return;
		}
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e)
			throws Exception {
		if (e.getChannel().isConnected()) {
			if (e.getCause() != null && e.getCause().getMessage() != null) {
				logger.warn("Exception {}", e.getCause().getMessage(),
						e.getCause());
			} else {
				logger.warn("Exception Received", e.getCause());
			}
			if (e.getCause() instanceof ClosedChannelException) {
				return;
			}
			if (handler != null) {
				try {
					status = handler.handleException(this, arguments, response, (Exception) e.getCause());
				} catch (Exception e2) {
				}
			}
			if (status == HttpResponseStatus.OK) {
				status = HttpResponseStatus.INTERNAL_SERVER_ERROR;
			}
			handler.sendResponse(this, e.getChannel(), arguments, response, status);
		}
	}

	@Override
	public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e)
			throws Exception {
		super.channelClosed(ctx, e);
		clean();
	}
}
