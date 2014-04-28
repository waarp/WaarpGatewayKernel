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

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;

import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.Cookie;
import org.jboss.netty.handler.codec.http.CookieDecoder;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.jboss.netty.handler.codec.http.QueryStringEncoder;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.waarp.common.crypto.HmacSha256;
import org.waarp.common.exception.CryptoException;
import org.waarp.common.json.JsonHandler;
import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;
import org.waarp.common.role.RoleDefault;
import org.waarp.common.role.RoleDefault.ROLE;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;
import org.waarp.gateway.kernel.exception.HttpInvalidAuthenticationException;
import org.waarp.gateway.kernel.rest.HttpRestHandler.METHOD;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author "Frederic Bregier"
 *
 */
public class RestArgument {
	/**
     * Internal Logger
     */
    private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
            .getLogger(RestArgument.class);
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
	 * arguments.path(ARGS_ANSWER) main entry for ANSWER arguments
	 */
	public static final String ARGS_ANSWER = "answer";
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
	 * arguments.path(ARG_X_AUTH_KEY).asText() = Key used
	 */
	public static final String ARG_X_AUTH_KEY = "X-Auth-Key";
	/**
	 * arguments.path(ARG_X_AUTH_KEY).asText() = Key used
	 */
	public static final String ARG_X_AUTH_USER = "X-Auth-User";
	/**
	 * Internal Key used (not to be passed through wire)
	 */
	public static final String ARG_X_AUTH_INTERNALKEY = "X-Auth-InternalKey";
	/**
	 * arguments.path(ARG_X_AUTH_TIMESTAMP).asText() = Timestamp in ISO 8601 format
	 */
	public static final String ARG_X_AUTH_TIMESTAMP = "X-Auth-Timestamp";
	/**
	 * arguments.path(ARG_X_AUTH_ROLE).asInt() = Role used
	 */
	public static final String ARG_X_AUTH_ROLE = "X-Auth-Role";
	/**
	 * Key for authentication in SHA-256
	 *
	 */
	protected static final HmacSha256 hmacSha256 = new HmacSha256();
	public static void initializeKey(String authentKey) {
		hmacSha256.setSecretKey(authentKey.getBytes(WaarpStringUtils.UTF8));
	}
	public static void initializeKey(File authentKey) throws CryptoException, IOException {
		hmacSha256.setSecretKey(authentKey);
	}
	
	ObjectNode arguments;
	public static final String JSON_PATH = "PATH";
	public static final String JSON_JSON = "json";
	public static final String JSON_COMMAND = "command";
	public static final String X_DETAILED_ALLOW = "DetailedAllow";
	public static final String X_ALLOW_URIS = "UriAllowed";
	
	public RestArgument(ObjectNode emptyArgument) {
		arguments = emptyArgument;
	}
	
	public void clean() {
		arguments.removeAll();
	}

	public void setRequest(HttpRequest request) {
		arguments.put(ARG_HASBODY, (request.isChunked() || request.getContent() != ChannelBuffers.EMPTY_BUFFER));
		arguments.put(ARG_METHOD, request.getMethod().getName());
		QueryStringDecoder decoderQuery = new QueryStringDecoder(request.getUri());
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
		Map<String, List<String>> map = decoderQuery.getParameters();
		ObjectNode node = arguments.putObject(ARGS_URI);
		for (String key : map.keySet()) {
			if (key.equalsIgnoreCase(ARG_X_AUTH_KEY)) {
				arguments.put(ARG_X_AUTH_KEY, map.get(key).get(0));
				continue;
			}
			if (key.equalsIgnoreCase(ARG_X_AUTH_USER)) {
				arguments.put(ARG_X_AUTH_USER, map.get(key).get(0));
				continue;
			}
			if (key.equalsIgnoreCase(ARG_X_AUTH_TIMESTAMP)) {
				arguments.put(ARG_X_AUTH_TIMESTAMP, map.get(key).get(0));
				continue;
			}
			ArrayNode array = node.putArray(key);
			for (String val : map.get(key)) {
				array.add(val);
			}
		}
	}
	/**
	 * Set X_AUTH, Method, Path and Cookie from source
	 * @param source
	 */
	public void setFromArgument(RestArgument source) {
		if (source.arguments.has(ARG_X_AUTH_USER)) {
			arguments.put(ARG_X_AUTH_USER, source.arguments.get(ARG_X_AUTH_USER).asText());
		}
		if (source.arguments.has(ARG_METHOD)) {
			arguments.put(ARG_METHOD, source.arguments.get(ARG_METHOD).asText());
		}
		if (source.arguments.has(ARG_PATH)) {
			arguments.put(ARG_PATH, source.arguments.get(ARG_PATH).asText());
		}
		if (source.arguments.has(ARG_BASEPATH)) {
			arguments.put(ARG_BASEPATH, source.arguments.get(ARG_BASEPATH).asText());
		}
		if (source.arguments.has(ARGS_COOKIE)) {
			arguments.putObject(ARGS_COOKIE).putAll((ObjectNode) source.arguments.get(ARGS_COOKIE));
		}
		logger.warn("DEBUG: {}\n {}", arguments, source);
	}
	
	public String getUri() {
		return arguments.path(ARG_PATH).asText();
	}
	public String getBaseUri() {
		return arguments.path(ARG_BASEPATH).asText();
	}
	/**
	 * 
	 * @return An iterator of JsonNode, which values can be retrieved by item.asText()
	 */
	public Iterator<JsonNode> getSubUri() {
		return arguments.path(ARGS_SUBPATH).elements();
	}
	public int getSubUriSize() {
		return arguments.path(ARGS_SUBPATH).size();
	}
	public String getXAuthKey() {
		return arguments.path(ARG_X_AUTH_KEY).asText();
	}
	public String getXAuthUser() {
		return arguments.path(ARG_X_AUTH_USER).asText();
	}
	public String getXAuthTimestamp() {
		return arguments.path(ARG_X_AUTH_TIMESTAMP).asText();
	}
	public void setXAuthRole(RoleDefault role) {
		arguments.put(ARG_X_AUTH_ROLE, role.getRoleAsByte());
	}
	public ROLE getXAuthRole() {
		byte role = (byte) arguments.get(ARG_X_AUTH_ROLE).asInt();
		return ROLE.fromByte(role);
	}
	/**
	 * 
	 * @return The ObjectNode containing all couples key/value
	 */
	public ObjectNode getUriArgs() {
		JsonNode node = arguments.path(ARGS_URI);
		if (node == null || node.isMissingNode()) {
			node = arguments.putObject(ARGS_URI);
		}
		return (ObjectNode) node;
	}
	
	/**
	 * 
	 * @return the method or null
	 */
	public METHOD getMethod() {
		String text = arguments.path(ARG_METHOD).asText();
		if (text == null || text.isEmpty()) {
			return null;
		}
		return METHOD.valueOf(text);
	}
	

	/**
	 * set values from Header into arguments.path(ARGS_HEADER)
	 * 
	 * @throws HttpIncorrectRequestException
	 */
	public void setHeaderArgs(List<Entry<String,String>> list) {
		ObjectNode node = (ObjectNode) arguments.get(ARGS_HEADER);
		if (node == null || node.isMissingNode()) {
			node = arguments.putObject(ARGS_HEADER);
		}
		for (Entry<String, String> entry : list) {
			String key = entry.getKey();
			if (! key.equals(HttpHeaders.Names.COOKIE)) {
				if (key.equalsIgnoreCase(ARG_X_AUTH_KEY)) {
					arguments.put(ARG_X_AUTH_KEY, entry.getValue());
					continue;
				}
				if (key.equalsIgnoreCase(ARG_X_AUTH_USER)) {
					arguments.put(ARG_X_AUTH_USER, entry.getValue());
					continue;
				}
				if (key.equalsIgnoreCase(ARG_X_AUTH_TIMESTAMP)) {
					arguments.put(ARG_X_AUTH_TIMESTAMP, entry.getValue());
					continue;
				}
				node.put(entry.getKey(), entry.getValue());
			}
		}
	}
	/**
	 * 
	 * @return The ObjectNode containing all couples key/value
	 */
	public ObjectNode getHeaderArgs() {
		JsonNode node = arguments.path(ARGS_HEADER);
		if (node == null || node.isMissingNode()) {
			node = arguments.putObject(ARGS_HEADER);
		}
		return (ObjectNode) node;
	}
	/**
	 * set method From URI
	 */
	public void methodFromUri() {
		JsonNode node = arguments.path(ARGS_URI).path(ARG_METHOD);
		if (! node.isMissingNode()) {
			// override
			arguments.put(ARG_METHOD, node.asText());
		}
	}
	/**
	 * set method From Header
	 */
	public void methodFromHeader() {
		JsonNode node = arguments.path(ARGS_HEADER).path(ARG_METHOD);
		if (! node.isMissingNode()) {
			// override
			arguments.put(ARG_METHOD, node.asText());
		}
	}

	/**
	 * set values from Cookies into arguments.path(ARGS_COOKIE)
	 * 
	 */
	public void setCookieArgs(String cookieString) {
		Set<Cookie> cookies;
		if (cookieString == null) {
			cookies = Collections.emptySet();
		} else {
			CookieDecoder decoder = new CookieDecoder();
			cookies = decoder.decode(cookieString);
		}
		if (!cookies.isEmpty()) {
			ObjectNode node = arguments.putObject(ARGS_COOKIE);
			for (Cookie cookie : cookies) {
				node.put(cookie.getName(), cookie.getValue());
			}
		}
	}
	/**
	 * 
	 * @return The ObjectNode containing all couples key/value
	 */
	public ObjectNode getCookieArgs() {
		JsonNode node = arguments.path(ARGS_COOKIE);
		if (node == null || node.isMissingNode()) {
			node = arguments.putObject(ARGS_COOKIE);
		}
		return (ObjectNode) node;
	}
	/**
	 * 
	 * @return The ObjectNode containing all couples key/value
	 */
	public ObjectNode getBody() {
		JsonNode node = arguments.path(ARGS_BODY);
		if (node == null || node.isMissingNode()) {
			node = arguments.putObject(ARGS_BODY);
		}
		return (ObjectNode) node;
	}
	/**
	 * 
	 * @return The ObjectNode containing all couples key/value
	 */
	public ObjectNode getAnswer() {
		JsonNode node = arguments.path(ARGS_ANSWER);
		if (node == null || node.isMissingNode()) {
			node = arguments.putObject(ARGS_ANSWER);
		}
		return (ObjectNode) node;
	}
	public void addItem(String name, String value) {
		getAnswer().put(name, value);
	}
	public String getItem(String name) {
		JsonNode node = getAnswer().get(name);
		if (node == null || node.isMissingNode()) {
			return null;
		}
		return node.asText();
	}
	public void addItems(ObjectNode node) {
		getAnswer().putAll(node);
	}
	/**
	 * The encoder is completed with extra necessary URI part containing ARG_X_AUTH_TIMESTAMP & ARG_X_AUTH_KEY
	 * 
	 * @param encoder
	 * @param extraKey
	 * 
	 * @throws HttpInvalidAuthenticationException if the computation of the authentication failed
	 */
	public static void getBaseAuthent(QueryStringEncoder encoder, String extraKey) throws HttpInvalidAuthenticationException {
		QueryStringDecoder decoderQuery = new QueryStringDecoder(encoder.toString());
		Map<String, List<String>> map = decoderQuery.getParameters();
		TreeMap<String, String> treeMap = new TreeMap<String, String>();
		for (Entry<String, List<String>> entry : map.entrySet()) {
			String keylower = entry.getKey().toLowerCase();
			List<String> values = entry.getValue();
			if (values != null && ! values.isEmpty()) {
				String last = values.get(values.size()-1);
				treeMap.put(keylower, last);
			}
		}
		DateTime date = new DateTime();
		treeMap.put(ARG_X_AUTH_TIMESTAMP.toLowerCase(), date.toString());
		try {
			String key = computeKey(extraKey, treeMap, decoderQuery.getPath());
			encoder.addParam(ARG_X_AUTH_TIMESTAMP, date.toString());
			encoder.addParam(ARG_X_AUTH_KEY, key);
		} catch (Exception e) {
			throw new HttpInvalidAuthenticationException(e);
		}
		
	}
    /**
     * This implementation of authentication is as follow: if X_AUTH is included in the URI or Header<br>
     * 0) Check that timestamp is correct (|curtime - timestamp| < maxinterval) from ARG_X_AUTH_TIMESTAMP, if maxInterval is 0, not mandatory<br>
     * 1) Get all URI args (except ARG_X_AUTH_KEY itself, but including timestamp), lowered case, in alphabetic order<br>
     * 2) Add an extra Key if not null (from ARG_X_AUTH_INTERNALKEY)<br>
     * 3) Compute an hash (SHA-1 or SHA-256)<br>
     * 4) Compare this hash with ARG_X_AUTH_KEY<br>
     * 
     * @param extraKey will be added as ARG_X_AUTH_INTERNALKEY
     * @param maxInterval ARG_X_AUTH_TIMESTAMP will be tested if value > 0
	 * @throws HttpInvalidAuthenticationException if the authentication failed
	 */
	public void checkBaseAuthent(String extraKey, long maxInterval) throws HttpInvalidAuthenticationException {
		TreeMap<String, String> treeMap = new TreeMap<String, String>();
		String argPath = getUri();
		ObjectNode arguri = getUriArgs();
		if (arguri == null) {
			throw new HttpInvalidAuthenticationException("Not enough argument");
		}
		Iterator<String> iteratorKey = arguri.fieldNames();
		DateTime dateTime = new DateTime();
		DateTime received = null;
		while (iteratorKey.hasNext()) {
			String key = iteratorKey.next();
			if (key.equalsIgnoreCase(ARG_X_AUTH_KEY)) {
				continue;
			}
			if (key.equalsIgnoreCase(ARG_X_AUTH_TIMESTAMP)) {
				received = DateTime.parse(arguri.get(ARG_X_AUTH_TIMESTAMP).asText());
			}
			String keylower = key.toLowerCase();
			ArrayNode values = (ArrayNode) arguri.get(key);
			if (values != null && values.size() > 0) {
				JsonNode jsonNode = values.get(values.size()-1);
				treeMap.put(keylower, jsonNode.asText());
			}
		}
		if (received == null) {
			String date = getXAuthTimestamp();
			received = DateTime.parse(date);
			treeMap.put(ARG_X_AUTH_TIMESTAMP.toLowerCase(), date);
		}
		String user = getXAuthUser();
		if (user != null && ! user.isEmpty()) {
			treeMap.put(ARG_X_AUTH_USER.toLowerCase(), user);
		}
		if (maxInterval > 0 && received != null) {
			Duration duration = new Duration(received, dateTime);
			if (Math.abs(duration.getMillis()) >= maxInterval) {
				throw new HttpInvalidAuthenticationException("timestamp is not compatible with the maximum delay allowed");
			}
		} else if (maxInterval > 0) {
			throw new HttpInvalidAuthenticationException("timestamp absent while required");
		}
		String key = computeKey(extraKey, treeMap, argPath);
		if (! key.equalsIgnoreCase(getXAuthKey())) {
			throw new HttpInvalidAuthenticationException("Invalid Authentication Key");
		}

	}

	/**
	 * @param extraKey
	 * @param treeMap
	 * @param argPath
	 * @throws HttpInvalidAuthenticationException
	 */
	protected static String computeKey(String extraKey, TreeMap<String, String> treeMap, String argPath) throws HttpInvalidAuthenticationException {
		Set<String> keys = treeMap.keySet();
		StringBuilder builder = new StringBuilder(argPath);
		if (! keys.isEmpty() || extraKey != null) {
			builder.append('?');
		}
		boolean first = true;
		for (String keylower : keys) {
			if (first) {
				first = false;
			} else {
				builder.append('&');
			}
			builder.append(keylower);
			builder.append('=');
			builder.append(treeMap.get(keylower));
		}
		if (extraKey != null) {
			if (!keys.isEmpty()) {
				builder.append("&");
			}
			builder.append(ARG_X_AUTH_INTERNALKEY);
			builder.append("=");
			builder.append(extraKey);
		}
		logger.debug("to sign: {}", builder);
		try {
			return hmacSha256.cryptToHex(builder.toString());
		} catch (Exception e) {
			throw new HttpInvalidAuthenticationException(e);
		}
	}

	@Override
	public String toString() {
		return JsonHandler.writeAsString(arguments);
	}

}
