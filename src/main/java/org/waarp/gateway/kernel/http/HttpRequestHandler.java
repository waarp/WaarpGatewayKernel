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
package org.waarp.gateway.kernel.http;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.Cookie;
import org.jboss.netty.handler.codec.http.CookieDecoder;
import org.jboss.netty.handler.codec.http.CookieEncoder;
import org.jboss.netty.handler.codec.http.DefaultCookie;
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
import org.jboss.netty.handler.codec.http.multipart.FileUpload;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.EndOfDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.ErrorDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.HttpPostRequestDecoder.NotEnoughDataDecoderException;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;
import org.jboss.netty.util.CharsetUtil;
import org.waarp.common.crypto.ssl.WaarpSslUtility;
import org.waarp.common.database.data.AbstractDbData.UpdatedInfo;
import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.AbstractHttpBusinessRequest;
import org.waarp.gateway.kernel.AbstractHttpField;
import org.waarp.gateway.kernel.HttpBusinessFactory;
import org.waarp.gateway.kernel.HttpPage;
import org.waarp.gateway.kernel.HttpPageHandler;
import org.waarp.gateway.kernel.AbstractHttpField.FieldPosition;
import org.waarp.gateway.kernel.AbstractHttpField.FieldRole;
import org.waarp.gateway.kernel.HttpPage.PageRole;
import org.waarp.gateway.kernel.database.DbConstant;
import org.waarp.gateway.kernel.database.WaarpActionLogger;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.session.DefaultHttpAuth;
import org.waarp.gateway.kernel.session.HttpSession;

/**
 * @author "Frederic Bregier"
 * 
 */
public abstract class HttpRequestHandler extends SimpleChannelUpstreamHandler {
	/**
	 * Internal Logger
	 */
	private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
			.getLogger(HttpRequestHandler.class);

	private static final Random random = new Random(System.currentTimeMillis());
	
	protected String baseStaticPath;
	protected String cookieSession;
	protected HttpPageHandler httpPageHandler;

	/**
	 * @param baseStaticPath
	 * @param cookieSession
	 * @param httpPageHandler
	 */
	public HttpRequestHandler(String baseStaticPath, String cookieSession,
			HttpPageHandler httpPageHandler) {
		this.baseStaticPath = baseStaticPath;
		this.cookieSession = cookieSession;
		this.httpPageHandler = httpPageHandler;
	}

	protected HttpSession session;
	protected HttpPostRequestDecoder decoder = null;
	protected HttpPage httpPage;
	protected AbstractHttpBusinessRequest businessRequest;

	protected HttpResponseStatus status = HttpResponseStatus.OK;
	protected String errorMesg;

	protected HttpRequest request;
	protected HttpMethod method;

	protected volatile boolean willClose = false;

	protected volatile boolean readingChunks = false;

	/**
	 * Clean method
	 * 
	 * Override if needed
	 */
	protected void clean() {
		if (businessRequest != null) {
			businessRequest.cleanRequest();
			businessRequest = null;
		}
		if (decoder != null) {
			decoder.cleanFiles();
			decoder = null;
		}
		if (session != null) {
			session.setFilename(null);
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
		willClose = false;
		status = HttpResponseStatus.OK;
		httpPage = null;
		businessRequest = null;
	}

	/**
	 * set values from URI
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void getUriArgs() throws HttpIncorrectRequestException {
		QueryStringDecoder decoderQuery = new QueryStringDecoder(
				request.getUri());
		Map<String, List<String>> uriAttributes = decoderQuery.getParameters();
		Set<String> attributes = uriAttributes.keySet();
		for (String name : attributes) {
			List<String> values = uriAttributes.get(name);
			if (values != null) {
				if (values.size() == 1) {
					// only one element is allowed
					httpPage.setValue(businessRequest, name, values.get(0), FieldPosition.URL);
				} else if (values.size() > 1) {
					// more than one element is not allowed
					values.clear();
					values = null;
					attributes = null;
					uriAttributes = null;
					decoderQuery = null;
					throw new HttpIncorrectRequestException("Too many values for " + name);
				}
				values.clear();
			}
			values = null;
		}
		attributes = null;
		uriAttributes = null;
		decoderQuery = null;
	}

	/**
	 * set values from Header
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void getHeaderArgs() throws HttpIncorrectRequestException {
		Set<String> headerNames = request.headers().names();
		for (String name : headerNames) {
			List<String> values = request.headers().getAll(name);
			if (values != null) {
				if (values.size() == 1) {
					// only one element is allowed
					httpPage.setValue(businessRequest, name, values.get(0), FieldPosition.HEADER);
				} else if (values.size() > 1) {
					// more than one element is not allowed
					values.clear();
					values = null;
					headerNames = null;
					throw new HttpIncorrectRequestException("Too many values for " + name);
				}
				values.clear();
			}
			values = null;
		}
		headerNames = null;
	}

	/**
	 * set values from Cookies
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	protected void getCookieArgs() throws HttpIncorrectRequestException {
		Set<Cookie> cookies;
		String value = request.headers().get(HttpHeaders.Names.COOKIE);
		if (value == null) {
			cookies = Collections.emptySet();
		} else {
			CookieDecoder decoder = new CookieDecoder();
			cookies = decoder.decode(value);
		}
		if (!cookies.isEmpty()) {
			for (Cookie cookie : cookies) {
				if (isCookieValid(cookie)) {
					httpPage.setValue(businessRequest, cookie.getName(), cookie.getValue(),
							FieldPosition.COOKIE);
				}
			}
		}
		cookies.clear();
		cookies = null;
	}

	/**
	 * To be used for instance to check correctness of connection
	 * 
	 * @param channel
	 */
	protected abstract void checkConnection(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Called when an error is raised. Note that clean() will be called just after.
	 * 
	 * @param channel
	 */
	protected abstract void error(Channel channel);

	@Override
	public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) {
		Channel channel = ctx.getChannel();
		try {
			if (!readingChunks) {
				initialize();
				this.request = (HttpRequest) e.getMessage();
				method = this.request.getMethod();
				QueryStringDecoder queryStringDecoder = new QueryStringDecoder(request.getUri());
				String uriRequest = queryStringDecoder.getPath();
				HttpPage httpPageTemp;
				try {
					httpPageTemp = httpPageHandler.getHttpPage(uriRequest,
							method.getName(), session);
				} catch (HttpIncorrectRequestException e1) {
					// real error => 400
					status = HttpResponseStatus.BAD_REQUEST;
					errorMesg = e1.getMessage();
					writeErrorPage(channel);
					return;
					// end of task
				}
				if (httpPageTemp == null) {
					// if Get => standard Get
					if (method == HttpMethod.GET) {
						logger.debug("simple get: " + this.request.getUri());
						// send content (image for instance)
						HttpWriteCacheEnable.writeFile(request, channel,
								baseStaticPath + uriRequest, cookieSession);
						return;
						// end of task
					} else {
						// real error => 404
						status = HttpResponseStatus.NOT_FOUND;
						writeErrorPage(channel);
						return;
					}
				}
				httpPage = httpPageTemp;
				session.setCurrentCommand(httpPage.pagerole);
				WaarpActionLogger.logCreate(DbConstant.admin.session, "Request received: "
						+ httpPage.pagename, session);
				if (httpPageTemp.pagerole == PageRole.ERROR) {
					status = HttpResponseStatus.BAD_REQUEST;
					error(channel);
					clean();
					// order is important: first clean, then create new businessRequest
					this.businessRequest = httpPage.newRequest(channel.getRemoteAddress());
					willClose = true;
					writeSimplePage(channel);
					WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
							"Error: " + httpPage.pagename, status);
					return;
					// end of task
				}
				this.businessRequest = httpPage.newRequest(channel.getRemoteAddress());
				getUriArgs();
				getHeaderArgs();
				getCookieArgs();
				checkConnection(channel);
				switch (httpPage.pagerole) {
					case DELETE:
						// no body element
						delete(e);
						return;
					case GETDOWNLOAD:
						// no body element
						getFile(channel);
						return;
					case HTML:
					case MENU:
						// no body element
						beforeSimplePage(channel);
						writeSimplePage(channel);
						return;
					case POST:
					case POSTUPLOAD:
					case PUT:
						post(e);
						return;
					default:
						// real error => 400
						status = HttpResponseStatus.BAD_REQUEST;
						writeErrorPage(channel);
						return;
				}
			} else {
				// New chunk is received: only for Put, Post or PostMulti!
				postChunk(e);
			}
		} catch (HttpIncorrectRequestException e1) {
			// real error => 400
			if (status == HttpResponseStatus.OK) {
				status = HttpResponseStatus.BAD_REQUEST;
			}
			errorMesg = e1.getMessage();
			logger.warn("Error", e1);
			writeErrorPage(channel);
		}
	}

	/**
	 * Utility to prepare error
	 * 
	 * @param channel
	 * @param message
	 * @throws HttpIncorrectRequestException
	 */
	protected void prepareError(Channel channel, String message)
			throws HttpIncorrectRequestException {
		logger.debug("Debug " + message);
		if (!setErrorPage(channel)) {
			// really really bad !
			return;
		}
		errorMesg = status.getReasonPhrase() + " / " + message;
		throw new HttpIncorrectRequestException(errorMesg);
	}

	/**
	 * Instantiate the page and the businessRequest handler
	 * 
	 * @param channel
	 * @return True if initialized
	 */
	protected boolean setErrorPage(Channel channel) {
		httpPage = httpPageHandler.getHttpPage(status.getCode());
		if (httpPage == null) {
			return false;
		}
		this.businessRequest = httpPage.newRequest(channel.getRemoteAddress());
		return true;
	}

	/**
	 * Write an error page
	 * 
	 * @param channel
	 */
	protected void writeErrorPage(Channel channel) {
		WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
				"Error: " + (httpPage == null ? "no page" : httpPage.pagename), status);
		error(channel);
		clean();
		willClose = true;
		if (!setErrorPage(channel)) {
			// really really bad !
			forceClosing(channel);
			return;
		}
		try {
			writeSimplePage(channel);
		} catch (HttpIncorrectRequestException e) {
			// force channel closing
			forceClosing(channel);
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
			response.headers().set(HttpHeaders.Names.CONTENT_TYPE, "text/html");
			response.headers().set(HttpHeaders.Names.REFERER, request.getUri());
			String answer = "<html><body>Error " + status.getReasonPhrase() + "</body></html>";
			response.setContent(ChannelBuffers.wrappedBuffer(answer.getBytes(WaarpStringUtils.UTF8)));
			ChannelFuture future = channel.write(response);
			logger.debug("Will close");
			future.addListener(WaarpSslUtility.SSLCLOSE);
		}
		WaarpActionLogger.logErrorAction(DbConstant.admin.session, session,
				"Error: " + httpPage.pagename, status);
	}

	/**
	 * Write a simple page from current httpPage and businessRequest
	 * 
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	protected void writeSimplePage(Channel channel) throws HttpIncorrectRequestException {
		logger.debug("HttpPage: " + (httpPage != null ? httpPage.pagename : "no page") +
				" businessRequest: "
				+ (businessRequest != null ? businessRequest.getClass().getName() : "no BR"));
		if (httpPage.pagerole == PageRole.ERROR) {
			try {
				httpPage.setValue(businessRequest, AbstractHttpField.ERRORINFO, errorMesg,
						FieldPosition.BODY);
			} catch (HttpIncorrectRequestException e) {
				// ignore
			}
		}
		String answer = httpPage.getHtmlPage(this.businessRequest);
		HttpResponse response = getResponse();
		int length = 0;
		// Convert the response content to a ChannelBuffer.
		ChannelBuffer buf = ChannelBuffers.wrappedBuffer(answer.getBytes(CharsetUtil.UTF_8));
		response.headers().set(HttpHeaders.Names.CONTENT_TYPE, this.businessRequest.getContentType());
		response.headers().set(HttpHeaders.Names.REFERER, request.getUri());
		length = buf.readableBytes();
		response.setContent(buf);
		if (!willClose) {
			// There's no need to add 'Content-Length' header
			// if this is the last response.
			response.headers().set(HttpHeaders.Names.CONTENT_LENGTH,
					String.valueOf(length));
		}
		// Write the response.
		ChannelFuture future = channel.write(response);
		// Close the connection after the write operation is done if necessary.
		if (willClose) {
			logger.debug("Will close");
			future.addListener(WaarpSslUtility.SSLCLOSE);
		}
	}

	/**
	 * Could be used for other method (as validation of an authent cookie)
	 * 
	 * @param cookie
	 * @return True if this cookie is valid
	 */
	protected abstract boolean isCookieValid(Cookie cookie);

	/**
	 * Method to add specific Cookies from business definition
	 * 
	 * Override if needed
	 * 
	 * @param response
	 * @param cookieNames
	 */
	protected void addBusinessCookie(HttpResponse response, Set<String> cookieNames) {
		for (AbstractHttpField field : httpPage.getFieldsForRequest(businessRequest).values()) {
			if (field.fieldcookieset && !cookieNames.contains(field.fieldname)) {
				Cookie cookie = new DefaultCookie(field.fieldname, field.fieldvalue);
				CookieEncoder cookieEncoder = new CookieEncoder(true);
				cookieEncoder.addCookie(cookie);
				response.headers().add(HttpHeaders.Names.SET_COOKIE, cookieEncoder.encode());
			}
		}
	}

	/**
	 * Method to set Cookies in response
	 * 
	 * @param response
	 */
	protected void setCookieEncoder(HttpResponse response) {
		Set<Cookie> cookies;
		String value = request.headers().get(HttpHeaders.Names.COOKIE);
		if (value == null) {
			cookies = Collections.emptySet();
		} else {
			CookieDecoder decoder = new CookieDecoder();
			cookies = decoder.decode(value);
		}
		boolean foundCookieSession = false;
		Set<String> cookiesName = new HashSet<String>();
		if (!cookies.isEmpty()) {
			// Reset the cookies if necessary.
			for (Cookie cookie : cookies) {
				if (isCookieValid(cookie)) {
					CookieEncoder cookieEncoder = new CookieEncoder(true);
					cookieEncoder.addCookie(cookie);
					response.headers().add(HttpHeaders.Names.SET_COOKIE, cookieEncoder.encode());
					if (cookie.getName().equals(cookieSession)) {
						foundCookieSession = true;
					}
					cookiesName.add(cookie.getName());
				}
			}
		}
		if (!foundCookieSession) {
			CookieEncoder cookieEncoder = new CookieEncoder(true);
			Cookie cookie = new DefaultCookie(cookieSession, session.getCookieSession());
			cookieEncoder.addCookie(cookie);
			response.headers().add(HttpHeaders.Names.SET_COOKIE, cookieEncoder.encode());
			cookiesName.add(cookie.getName());
		}
		addBusinessCookie(response, cookiesName);
		cookiesName.clear();
		cookiesName = null;
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
			setCookieEncoder(response);
			willClose = true;
			return response;
		}
		boolean keepAlive = HttpHeaders.isKeepAlive(request);
		willClose = willClose ||
				status != HttpResponseStatus.OK ||
				HttpHeaders.Values.CLOSE.equalsIgnoreCase(request
						.headers().get(HttpHeaders.Names.CONNECTION)) ||
				request.getProtocolVersion().equals(HttpVersion.HTTP_1_0) &&
				!keepAlive;
		if (willClose) {
			keepAlive = false;
		}
		// Build the response object.
		HttpResponse response = new DefaultHttpResponse(
				request.getProtocolVersion(), status);
		if (keepAlive) {
			response.headers().set(HttpHeaders.Names.CONNECTION,
					HttpHeaders.Values.KEEP_ALIVE);
		}
		setCookieEncoder(response);
		return response;
	}

	/**
	 * 
	 * @return the filename used for this request
	 */
	protected abstract String getFilename();

	/**
	 * Called before simple Page is called (Menu or HTML)
	 * 
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	protected abstract void beforeSimplePage(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Method that will use the result and send back the result
	 * 
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	protected void finalData(Channel channel) throws HttpIncorrectRequestException {
		try {
			businessValidRequestAfterAllDataReceived(channel);
			if (!httpPage.isRequestValid(businessRequest)) {
				throw new HttpIncorrectRequestException("Request unvalid");
			}
			switch (httpPage.pagerole) {
				case DELETE:
					session.setFilename(getFilename());
					finalDelete(channel);
					WaarpActionLogger.logAction(DbConstant.admin.session, session,
							"Delete OK", status, UpdatedInfo.DONE);
					break;
				case GETDOWNLOAD:
					finalGet(channel);
					WaarpActionLogger.logAction(DbConstant.admin.session, session,
							"Download OK", status, UpdatedInfo.DONE);
					break;
				case POST:
					finalPost(channel);
					WaarpActionLogger.logAction(DbConstant.admin.session, session,
							"Post OK", status, UpdatedInfo.DONE);
					break;
				case POSTUPLOAD:
					finalPostUpload(channel);
					WaarpActionLogger.logAction(DbConstant.admin.session, session,
							"PostUpload OK", status, UpdatedInfo.DONE);
					break;
				case PUT:
					finalPut(channel);
					WaarpActionLogger.logAction(DbConstant.admin.session, session,
							"Put OK", status, UpdatedInfo.DONE);
					break;
				default:
					// real error => 400
					status = HttpResponseStatus.BAD_REQUEST;
					throw new HttpIncorrectRequestException("Unknown request");
			}
		} catch (HttpIncorrectRequestException e) {
			// real error => 400
			if (status == HttpResponseStatus.OK) {
				status = HttpResponseStatus.BAD_REQUEST;
			}
			throw e;
		}
	}

	/**
	 * Method that will use the uploaded file and prepare the result
	 * 
	 * @param channel
	 */
	protected abstract void finalDelete(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Method that will use the uploaded file and send back the result <br>
	 * (this method must send back the answer using for instance a ChunkedInput handler and should
	 * try to call clean(), but taking into consideration that it will erase all data, so it must be
	 * ensured that all data are sent through the wire before calling it. Note however that when the
	 * connection is closed or when a new request on the same connection occurs, the clean method is
	 * automatically called. The usage of a HttpCleanChannelFutureListener on the last write might
	 * be useful.)
	 * 
	 * @param channel
	 */
	protected abstract void finalGet(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Method that will use the uploaded file and prepare the result
	 * 
	 * @param channel
	 */
	protected abstract void finalPostUpload(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Method that will use the post result and prepare the result
	 * 
	 * @param channel
	 */
	protected abstract void finalPost(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Method that will use the put result and prepare the result
	 * 
	 * @param channel
	 */
	protected abstract void finalPut(Channel channel) throws HttpIncorrectRequestException;

	/**
	 * Validate all data as they should be all received (done before the isRequestValid)
	 * 
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	public abstract void businessValidRequestAfterAllDataReceived(Channel channel)
			throws HttpIncorrectRequestException;

	/**
	 * Method that get "get" data, answer has to be written in the business part finalGet
	 * 
	 * @param channel
	 */
	protected void getFile(Channel channel) throws HttpIncorrectRequestException {
		finalData(channel);
	}

	/**
	 * Method that get delete data
	 * 
	 * @param e
	 */
	protected void delete(MessageEvent e) throws HttpIncorrectRequestException {
		finalData(e.getChannel());
		writeSimplePage(e.getChannel());
		clean();
	}

	/**
	 * Method that get post data
	 * 
	 * @param e
	 * @throws HttpIncorrectRequestException
	 */
	protected void post(MessageEvent e) throws HttpIncorrectRequestException {
		try {
			decoder = new HttpPostRequestDecoder(HttpBusinessFactory.factory, request);
		} catch (ErrorDataDecoderException e1) {
			status = HttpResponseStatus.NOT_ACCEPTABLE;
			throw new HttpIncorrectRequestException(e1);
		} catch (Exception e1) {
			// GETDOWNLOAD Method: should not try to create a HttpPostRequestDecoder
			// So OK but stop here
			status = HttpResponseStatus.NOT_ACCEPTABLE;
			throw new HttpIncorrectRequestException(e1);
		}

		if (request.isChunked()) {
			// Chunk version
			readingChunks = true;
		} else {
			// Not chunk version
			readHttpDataAllReceive(e.getChannel());
			finalData(e.getChannel());
			writeSimplePage(e.getChannel());
			clean();
		}
	}

	/**
	 * Method that get a chunk of data
	 * 
	 * @param e
	 * @throws HttpIncorrectRequestException
	 */
	protected void postChunk(MessageEvent e) throws HttpIncorrectRequestException {
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
		readHttpDataChunkByChunk(e.getChannel());
		// example of reading only if at the end
		if (chunk.isLast()) {
			readingChunks = false;
			finalData(e.getChannel());
			writeSimplePage(e.getChannel());
			clean();
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
			status = HttpResponseStatus.INTERNAL_SERVER_ERROR;
			writeErrorPage(e.getChannel());
		}
	}

	@Override
	public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e)
			throws Exception {
		super.channelClosed(ctx, e);
		clean();
	}

	/**
	 * Read all InterfaceHttpData from finished transfer
	 * 
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	protected void readHttpDataAllReceive(Channel channel) throws HttpIncorrectRequestException {
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
			readHttpData(data, channel);
		}
	}

	/**
	 * Read request by chunk and getting values from chunk to chunk
	 * 
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	protected void readHttpDataChunkByChunk(Channel channel) throws HttpIncorrectRequestException {
		try {
			while (decoder.hasNext()) {
				InterfaceHttpData data = decoder.next();
				if (data != null) {
					// new value
					readHttpData(data, channel);
				}
			}
		} catch (EndOfDataDecoderException e1) {
			// end
			return;
		}
	}

	/**
	 * Read one Data
	 * 
	 * @param data
	 * @param channel
	 * @throws HttpIncorrectRequestException
	 */
	protected void readHttpData(InterfaceHttpData data, Channel channel)
			throws HttpIncorrectRequestException {
		if (data.getHttpDataType() == HttpDataType.Attribute) {
			Attribute attribute = (Attribute) data;
			String name = attribute.getName();
			try {
				String value = attribute.getValue();
				httpPage.setValue(businessRequest, name, value, FieldPosition.BODY);
			} catch (IOException e) {
				// Error while reading data from File, only print name and
				// error
				attribute.delete();
				status = HttpResponseStatus.INTERNAL_SERVER_ERROR;
				throw new HttpIncorrectRequestException(e);
			}
			attribute.delete();
		} else if (data.getHttpDataType() == HttpDataType.FileUpload) {
			FileUpload fileUpload = (FileUpload) data;
			if (fileUpload.isCompleted()) {
				AbstractHttpField field =
						httpPage.getField(businessRequest, fileUpload.getName());
				if (field != null && field.fieldtype == FieldRole.BUSINESS_INPUT_FILE) {
					httpPage.setValue(businessRequest, field.fieldname, fileUpload);
				} else {
					logger.warn("File received but no variable for it");
					fileUpload.delete();
				}
			} else {
				logger.warn("File still pending but should not");
				fileUpload.delete();
			}
		} else {
			logger.warn("Unknown element: " + data.toString());
		}
	}

	/**
	 * Default Session Cookie generator
	 * 
	 * @return the new session cookie value
	 */
	protected String getNewCookieSession() {
		return "Waarp" + Long.toHexString(random.nextLong());
	}

	/**
	 * Default session creation
	 * 
	 * @param e
	 */
	protected void createNewSessionAtConnection(ChannelStateEvent e) {
		this.session = new HttpSession();
		this.session.setHttpAuth(new DefaultHttpAuth(session));
		this.session.setCookieSession(getNewCookieSession());
		this.session.setCurrentCommand(PageRole.HTML);
	}

	@Override
	public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
		super.channelConnected(ctx, e);
		createNewSessionAtConnection(e);
	}

}
