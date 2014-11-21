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

import org.jboss.netty.handler.codec.http.multipart.FileUpload;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;

/**
 * @author Frederic Bregier
 * 
 */
public abstract class AbstractHttpField implements Cloneable {

    public static enum FieldRole {
        BUSINESS_INPUT_TEXT,
        BUSINESS_INPUT_CHECKBOX,
        BUSINESS_INPUT_RADIO,
        BUSINESS_INPUT_HIDDEN,
        BUSINESS_INPUT_FILE,
        BUSINESS_INPUT_IMAGE,
        BUSINESS_INPUT_PWD,
        BUSINESS_TEXTAREA,
        BUSINESS_SELECT,
        SUBMIT,
        BUSINESS_COOKIE;
    }

    public static enum FieldPosition {
        URL,
        HEADER,
        COOKIE,
        BODY,
        ANY
    }

    /**
     * Special field name for Error page
     */
    public static final String ERRORINFO = "ERRORINFO";
    /*
     * fieldname, fieldtype, fieldinfo, fieldvalue, fieldvisibility, fieldmandatory, fieldcookieset,
     * fieldtovalidate, fieldposition, fieldrank
     */
    public String fieldname;
    public FieldRole fieldtype;
    public String fieldinfo;
    public String fieldvalue;
    public boolean fieldvisibility;
    public boolean fieldmandatory;
    public boolean fieldcookieset;
    public boolean fieldtovalidate;
    public FieldPosition fieldposition;
    public int fieldrank;
    public boolean present = false;
    public FileUpload fileUpload;

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
    public AbstractHttpField(String fieldname, FieldRole fieldtype, String fieldinfo,
            String fieldvalue, boolean fieldvisibility, boolean fieldmandatory,
            boolean fieldcookieset,
            boolean fieldtovalidate, FieldPosition fieldposition, int fieldrank) {
        this.fieldname = fieldname;
        this.fieldtype = fieldtype;
        this.fieldinfo = fieldinfo;
        this.fieldvalue = fieldvalue;
        this.fieldvisibility = fieldvisibility;
        this.fieldmandatory = fieldmandatory;
        this.fieldcookieset = fieldcookieset;
        this.fieldtovalidate = fieldtovalidate;
        this.fieldposition = fieldposition;
        this.fieldrank = fieldrank;
    }

    /**
     * 
     * @param page
     *            source HttpPage
     * @return the html form of a field according to its type and value
     */
    public abstract String getHtmlFormField(HttpPage page) throws HttpIncorrectRequestException;

    /**
     * 
     * @param page
     *            source HttpPage
     * @return the html tab of a field according to its type and value
     */
    public abstract String getHtmlTabField(HttpPage page) throws HttpIncorrectRequestException;

    @Override
    public abstract AbstractHttpField clone();

    /**
     * Set the value
     * 
     * @param value
     * @throws HttpIncorrectRequestException
     *             if the value was already set
     */
    public abstract void setStringValue(String value) throws HttpIncorrectRequestException;

    /**
     * Set the fileUpload
     * 
     * @param fileUpload
     * @throws HttpIncorrectRequestException
     *             if the value was already set
     */
    public abstract void setFileUpload(FileUpload fileUpload) throws HttpIncorrectRequestException;

    /**
     * Clean method
     */
    public void clean() {
        this.fieldname = null;
        this.fieldinfo = null;
        this.fieldvalue = null;
        this.present = false;
        if (this.fileUpload != null) {
            this.fileUpload.delete();
            this.fileUpload = null;
        }
    }
}
