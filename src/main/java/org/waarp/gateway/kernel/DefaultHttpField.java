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

import io.netty.handler.codec.http.multipart.FileUpload;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;

/**
 * @author Frederic Bregier
 * 
 */
public class DefaultHttpField extends AbstractHttpField {

	/**
	 * @param fieldname
	 * @param fieldtype
	 * @param fieldinfo
	 * @param fieldvalue
	 * @param fieldvisibility
	 * @param fieldmandatory
	 * @param fieldcookieset
	 * @param fieldtovalidate
	 * @param fieldposition
	 * @param fieldrank
	 */
	public DefaultHttpField(String fieldname, FieldRole fieldtype, String fieldinfo,
			String fieldvalue, boolean fieldvisibility, boolean fieldmandatory,
			boolean fieldcookieset,
			boolean fieldtovalidate, FieldPosition fieldposition, int fieldrank) {
		super(fieldname, fieldtype, fieldinfo, fieldvalue, fieldvisibility, fieldmandatory,
				fieldcookieset, fieldtovalidate, fieldposition, fieldrank);
	}

	@Override
	public String getHtmlFormField(HttpPage page) throws HttpIncorrectRequestException {
		StringBuilder builder = new StringBuilder();
		switch (this.fieldtype) {
			case BUSINESS_INPUT_CHECKBOX:
			case BUSINESS_INPUT_RADIO: {
				builder.append(fieldinfo);
				AbstractHttpField source = page.fields.get(fieldname);
				String[] values = source.fieldvalue.split(",");
				String[] finalValues = fieldvalue.split(",");
				String inputtype;
				if (fieldtype == FieldRole.BUSINESS_INPUT_CHECKBOX) {
					inputtype = ": <INPUT type=CHECKBOX name=";
				} else {
					inputtype = ": <INPUT type=RADIO name=";
				}
				for (String string : values) {
					builder.append(inputtype);
					builder.append(fieldname);
					if (fieldvalue != null && fieldvalue.length() > 0) {
						builder.append(" value=\"");
						builder.append(string);
						builder.append("\"");
						if (finalValues != null) {
							for (String value : finalValues) {
								if (value.equals(string)) {
									builder.append(" checked");
									break;
								}
							}
						}
					}
					builder.append('>');
					builder.append(string);
					builder.append("<BR>");
				}
				break;
			}
			case BUSINESS_INPUT_FILE:
			case BUSINESS_INPUT_HIDDEN:
			case BUSINESS_INPUT_PWD:
			case BUSINESS_INPUT_TEXT:
			case SUBMIT: {
				builder.append(fieldinfo);
				switch (this.fieldtype) {
					case BUSINESS_INPUT_FILE:
						builder.append(": <INPUT type=FILE name=");
						break;
					case BUSINESS_INPUT_HIDDEN:
						builder.append(": <INPUT type=HIDDEN name=");
						break;
					case BUSINESS_INPUT_PWD:
						builder.append(": <INPUT type=PASSWORD name=");
						break;
					case BUSINESS_INPUT_TEXT:
						builder.append(": <INPUT type=TEXT name=");
						break;
					case SUBMIT:
						builder.append(": <INPUT type=SUBMIT name=");
						break;
					default:
						throw new HttpIncorrectRequestException("Incorrect type: " + this.fieldtype);
				}
				builder.append(fieldname);
				if (fieldvalue != null && fieldvalue.length() > 0) {
					builder.append(" value=\"");
					builder.append(fieldvalue);
					builder.append("\"");
				}
				builder.append('>');
				break;
			}
			case BUSINESS_INPUT_IMAGE: {
				builder.append(fieldinfo);
				builder.append(": <INPUT type=IMAGE name=");
				builder.append(fieldname);
				if (fieldvalue != null && fieldvalue.length() > 0) {
					builder.append(" src=\"");
					builder.append(fieldvalue);
					builder.append("\" ");
				}
				if (fieldinfo != null && fieldinfo.length() > 0) {
					builder.append(" alt=\"");
					builder.append(fieldinfo);
					builder.append("\" ");
				}
				builder.append('>');
				break;
			}
			case BUSINESS_SELECT: {
				builder.append(fieldinfo);
				builder.append("<BR><SELECT name=");
				builder.append(fieldname);
				builder.append('>');
				AbstractHttpField source = page.fields.get(fieldname);
				String[] values = source.fieldvalue.split(",");
				for (String string : values) {
					builder.append("<OPTION label=\"");
					builder.append(string);
					builder.append("\" value=\"");
					builder.append(string);
					if (fieldvalue != null && fieldvalue.length() > 0 && fieldvalue.equals(string)) {
						builder.append("\" selected>");
					} else {
						builder.append("\">");
					}
					builder.append(string);
					builder.append("</OPTION>");
				}
				builder.append("</SELECT>");
				break;
			}
			case BUSINESS_TEXTAREA: {
				builder.append(fieldinfo);
				builder.append("<BR><TEXTAREA name=");
				builder.append(fieldname);
				builder.append('>');
				if (fieldvalue != null && fieldvalue.length() > 0) {
					builder.append(fieldvalue);
				}
				builder.append("</TEXTAREA>");
				break;
			}
			case BUSINESS_COOKIE:
				// no since Cookie
				break;
			default:
				throw new HttpIncorrectRequestException("Incorrect type: " + this.fieldtype);
		}
		return builder.toString();
	}

	@Override
	public String getHtmlTabField(HttpPage page) throws HttpIncorrectRequestException {
		StringBuilder builder = new StringBuilder();
		builder.append(fieldinfo);
		builder.append("</TD><TD>");
		if (fieldvalue != null) {
			builder.append(fieldvalue);
		}
		return builder.toString();
	}

	@Override
	public DefaultHttpField clone() {
		DefaultHttpField newField = new DefaultHttpField(fieldname, fieldtype, fieldinfo,
				fieldvalue,
				fieldvisibility, fieldmandatory, fieldcookieset, fieldtovalidate, fieldposition,
				fieldrank);
		return newField;
	}

	@Override
	public void setStringValue(String value) throws HttpIncorrectRequestException {
		switch (fieldtype) {
			case BUSINESS_INPUT_CHECKBOX:
				if (fieldvalue != null) {
					if (fieldvalue.length() > 0) {
						fieldvalue += "," + value;
					} else {
						fieldvalue = value;
					}
				} else {
					fieldvalue = value;
				}
				present = true;
				break;
			case BUSINESS_INPUT_FILE:
			case BUSINESS_INPUT_HIDDEN:
			case BUSINESS_INPUT_IMAGE:
			case BUSINESS_INPUT_PWD:
			case BUSINESS_INPUT_RADIO:
			case BUSINESS_INPUT_TEXT:
			case BUSINESS_SELECT:
			case BUSINESS_TEXTAREA:
			case BUSINESS_COOKIE:
				if (present) {
					// should not be
					throw new HttpIncorrectRequestException("Field already filled: " + fieldname);
				}
				fieldvalue = value;
				present = true;
				break;
			default:
				break;
		}
	}

	@Override
	public void setFileUpload(FileUpload fileUpload) throws HttpIncorrectRequestException {
		if (fieldtype == FieldRole.BUSINESS_INPUT_FILE) {
			if (present) {
				// should not be
				throw new HttpIncorrectRequestException("Field already filled: " + fieldname);
			}
			this.fileUpload = fileUpload;
			this.fieldvalue = fileUpload.getFilename();
			present = true;
		} else {
			// should not be
			throw new HttpIncorrectRequestException("Field with wrong type (should be File): "
					+ fieldname);
		}
	}

}
