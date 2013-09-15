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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import org.waarp.common.exception.InvalidArgumentException;
import org.waarp.common.json.JsonHandler;
import org.waarp.common.logging.WaarpInternalLogger;
import org.waarp.common.logging.WaarpInternalLoggerFactory;
import org.waarp.gateway.kernel.AbstractHttpField.FieldPosition;
import org.waarp.gateway.kernel.AbstractHttpField.FieldRole;
import org.waarp.gateway.kernel.HttpPage.PageRole;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;

/**
 * @author frederic bregier
 * 
 */
public class HttpJsonDefinition {
	/**
	 * Internal Logger
	 */
	private static final WaarpInternalLogger logger = WaarpInternalLoggerFactory
			.getLogger(HttpJsonDefinition.class);

	/*
	 * pagename, fileform, header, footer, beginform, endform, nextinform, uri, pagerole, errorpage,
	 * classname, <br> <fieldname, fieldtype, fieldinfo, fieldvalue, fieldvisibility,
	 * fieldmandatory, fieldcookieset, fieldtovalidate, fieldposition, fieldrank>*
	 */
	/*
	 * fieldname, fieldtype, fieldinfo, fieldvalue, fieldvisibility, fieldmandatory, fieldcookieset,
	 * fieldtovalidate, fieldposition, fieldrank
	 */

	/**
	 * Structure of the Configuration: Field
	 * 
	 */
	private static final class ConfigHttpField {
		// 1 field
		public String FIELDNAME;
		public FieldRole FIELDTYPE;
		public String FIELDINFO;
		public String FIELDVALUE;
		public boolean FIELDVISIBILITY;
		public boolean FIELDMANDATORY;
		public boolean FIELDCOOKIESET;
		public boolean FIELDTOVALIDATE;
		public FieldPosition FIELDPOSITION;
		public int FIELDRANK;
	}

	/**
	 * Structure of the Configuration: Page
	 * 
	 */
	private static final class ConfigHttpPage {
			// 1 Page
		public String PAGENAME;
		public String FILEFORM;
		public String HEADER;
		public String FOOTER;
		public String BEGINFORM;
		public String ENDFORM;
		public String NEXTINFORM;
		public String URI;
		public PageRole PAGEROLE;
		public String ERRORPAGE;
		public String CLASSNAME;
			// all fields
		public List<ConfigHttpField> FIELD;
	}

	/**
	 * Structure of the Configuration: Pages
	 * 
	 * from root => Pages.Page
	 * 
	 */
	private static final class ConfigHttpPages {
			// all pages
		public List<ConfigHttpPage> PAGE;
	}

	protected static AbstractHttpField loadHttpPage(ConfigHttpField fieldValue)
			throws InvalidArgumentException {
		return new DefaultHttpField(fieldValue.FIELDNAME, fieldValue.FIELDTYPE, fieldValue.FIELDINFO, 
				fieldValue.FIELDVALUE, fieldValue.FIELDVISIBILITY, fieldValue.FIELDMANDATORY, 
				fieldValue.FIELDCOOKIESET, fieldValue.FIELDTOVALIDATE, fieldValue.FIELDPOSITION,
				fieldValue.FIELDRANK);
	}

	protected static HttpPage loadHttpConfiguration(ConfigHttpPage cpage)
			throws InvalidArgumentException, ClassNotFoundException, InstantiationException,
			IllegalAccessException {
		List<ConfigHttpField> list = cpage.FIELD;
		LinkedHashMap<String, AbstractHttpField> linkedHashMap =
				new LinkedHashMap<String, AbstractHttpField>(list.size());
		// Now read the configuration
		for (ConfigHttpField fieldValue : list) {
			AbstractHttpField field = loadHttpPage(fieldValue);
			linkedHashMap.put(field.fieldname, field);
		}
		list.clear();
		list = null;
		return new HttpPage(cpage.PAGENAME, cpage.FILEFORM, cpage.HEADER, cpage.FOOTER, 
				cpage.BEGINFORM, cpage.ENDFORM, cpage.NEXTINFORM, cpage.URI, 
				cpage.PAGEROLE, cpage.ERRORPAGE, cpage.CLASSNAME, linkedHashMap);
	}

	/**
	 * Initiate the configuration from the json file for Http server
	 * 
	 * @param filename
	 * @return the List<HttpPage> if OK
	 * @throws InvalidArgumentException
	 * @throws ClassNotFoundException
	 * @throws IllegalAccessException
	 * @throws InstantiationException
	 */
	public static HttpPageHandler setConfigurationHttpServerFromJson(String filename)
			throws InvalidArgumentException, ClassNotFoundException, InstantiationException,
			IllegalAccessException {
		File file = new File(filename);
		ConfigHttpPages cpages;
		try {
			cpages = JsonHandler.mapper.readValue(file, ConfigHttpPages.class);
		} catch (JsonParseException e) {
			logger.error("Unable to read the JSON Config file: " + filename, e);
			throw new InvalidArgumentException("Unable to read JSON file: " + filename, e);
		} catch (JsonMappingException e) {
			logger.error("Unable to read the JSON Config file: " + filename, e);
			throw new InvalidArgumentException("Unable to read JSON file: " + filename, e);
		} catch (IOException e) {
			logger.error("Unable to read the JSON Config file: " + filename, e);
			throw new InvalidArgumentException("Unable to read JSON file: " + filename, e);
		}
		HashMap<String, HttpPage> pages = new HashMap<String, HttpPage>(cpages.PAGE.size());
		// Now read the configuration
		for (ConfigHttpPage cpage : cpages.PAGE) {
			HttpPage page = loadHttpConfiguration(cpage);
			pages.put(page.uri, page);
		}
		cpages.PAGE.clear();
		return new HttpPageHandler(pages);
	}


	protected static void addToField(List<ConfigHttpField> fields, AbstractHttpField field) {
		ConfigHttpField cfield = new ConfigHttpField();
		cfield.FIELDNAME = field.fieldname;
		cfield.FIELDTYPE = field.fieldtype;
		cfield.FIELDINFO = field.fieldinfo;
		cfield.FIELDVALUE = field.fieldvalue;
		cfield.FIELDVISIBILITY = field.fieldvisibility;
		cfield.FIELDMANDATORY = field.fieldmandatory;
		cfield.FIELDCOOKIESET = field.fieldcookieset;
		cfield.FIELDTOVALIDATE = field.fieldtovalidate;
		cfield.FIELDPOSITION = field.fieldposition;
		cfield.FIELDRANK = field.fieldrank;
		fields.add(cfield);
	}

	protected static void addToElement(List<ConfigHttpPage> pages, HttpPage page) {
		ConfigHttpPage cpage = new ConfigHttpPage();
		cpage.PAGENAME = page.pagename;
		cpage.FILEFORM = page.fileform;
		cpage.HEADER = page.header;
		cpage.FOOTER = page.footer;
		cpage.BEGINFORM = page.beginform;
		cpage.ENDFORM = page.endform;
		cpage.NEXTINFORM = page.nextinform;
		cpage.URI = page.uri;
		cpage.PAGEROLE = page.pagerole;
		cpage.ERRORPAGE = page.errorpage;
		cpage.CLASSNAME = page.classname;
		cpage.FIELD = new ArrayList<ConfigHttpField>();
		for (AbstractHttpField field : page.fields.values()) {
			addToField(cpage.FIELD, field);
		}
		pages.add(cpage);
	}

	public static void exportConfiguration(HttpPageHandler httpPageHandler, String filename)
			throws HttpIncorrectRequestException {
		ConfigHttpPages cpages = new ConfigHttpPages();
		cpages.PAGE = new ArrayList<ConfigHttpPage>();
		for (HttpPage page : httpPageHandler.hashmap.values()) {
			addToElement(cpages.PAGE, page);
		}
		File file = new File(filename);
		try {
			JsonHandler.mapper.writerWithDefaultPrettyPrinter().writeValue(file, cpages);
		} catch (JsonGenerationException e) {
			throw new HttpIncorrectRequestException("Cannot write file: " + filename, e);
		} catch (JsonMappingException e) {
			throw new HttpIncorrectRequestException("Cannot write file: " + filename, e);
		} catch (IOException e) {
			throw new HttpIncorrectRequestException("Cannot write file: " + filename, e);
		}
	}
}
