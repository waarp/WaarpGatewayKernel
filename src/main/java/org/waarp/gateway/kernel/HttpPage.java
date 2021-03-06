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

import java.net.SocketAddress;
import java.util.LinkedHashMap;

import io.netty.handler.codec.http.multipart.FileUpload;
import org.waarp.common.exception.FileTransferException;
import org.waarp.common.exception.InvalidArgumentException;
import org.waarp.common.logging.WaarpLogger;
import org.waarp.common.logging.WaarpLoggerFactory;
import org.waarp.common.utility.WaarpStringUtils;
import org.waarp.gateway.kernel.AbstractHttpField.FieldPosition;
import org.waarp.gateway.kernel.exception.HttpIncorrectRequestException;

/**
 * @author Frederic Bregier
 * 
 */
public class HttpPage {
    /**
     * Internal Logger
     */
    private static final WaarpLogger logger = WaarpLoggerFactory
            .getLogger(HttpPage.class);

    public static enum PageRole {
        HTML, MENU, GETDOWNLOAD, POST, PUT, POSTUPLOAD, DELETE, ERROR;
    }

    /*
     * pagename, fileform, header, footer, beginform, endform, nextinform, uri, pagerole, errorpage,
     * classname, fields
     */
    private String pagename;
    private String fileform;
    private String header;
    private String footer;
    private String beginform;
    private String endform;
    private String nextinform;
    private String uri;
    private PageRole pagerole;
    private String errorpage;
    private String classname;
    private LinkedHashMap<String, AbstractHttpField> fields;
    private HttpBusinessFactory httpBusinessFactory;

    /**
     * 
     * @param pagename
     * @param fileform
     * @param header
     * @param footer
     * @param beginform
     * @param endform
     * @param nextinform
     * @param uri
     * @param pagerole
     * @param errorpage
     * @param classname
     * @param fields
     * @throws ClassNotFoundException
     * @throws IllegalAccessException
     * @throws InstantiationException
     */
    public HttpPage(String pagename, String fileform, String header, String footer,
            String beginform, String endform, String nextinform,
            String uri, PageRole pagerole, String errorpage,
            String classname, LinkedHashMap<String, AbstractHttpField> fields)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        this.setPagename(pagename);
        this.setFileform(fileform);
        if (this.getFileform() != null && this.getFileform().length() == 0) {
            this.setFileform(null);
        }
        this.setHeader(header);
        this.setFooter(footer);
        this.setBeginform(beginform);
        this.setEndform(endform);
        this.setNextinform(nextinform);
        this.setUri(uri);
        this.setPagerole(pagerole);
        this.setErrorpage(errorpage);
        this.setClassname(classname);
        this.setFields(fields);
        @SuppressWarnings("unchecked")
        Class<HttpBusinessFactory> clasz = (Class<HttpBusinessFactory>) Class.forName(classname);
        this.setHttpBusinessFactory(clasz.newInstance());
    }

    /**
     * Called at the beginning of every request to get the current HttpBusinessFactory to use.
     * 
     * @param remoteAddress
     *            the remote socket address in use
     * @return AbstractHttpBusinessRequest to use during the request
     */
    public AbstractHttpBusinessRequest newRequest(SocketAddress remoteAddress) {
        LinkedHashMap<String, AbstractHttpField> linkedHashMap = new LinkedHashMap<String, AbstractHttpField>(
                this.getFields().size());
        for (AbstractHttpField field : this.getFields().values()) {
            AbstractHttpField newfield = field.clone();
            if (getPagerole() != PageRole.MENU) {
                newfield.fieldvalue = null;
            }
            linkedHashMap.put(field.getFieldname(), newfield);
        }
        return this.getHttpBusinessFactory().getNewHttpBusinessRequest(remoteAddress, linkedHashMap,
                this);
    }

    public String getPageValue(String value) {
        if (this.getFileform() != null && value != null) {
            try {
                return WaarpStringUtils.readFileException(getFileform() + value);
            } catch (InvalidArgumentException e) {
            } catch (FileTransferException e) {
            }
        }
        return value;
    }

    /**
     * 
     * @param reference
     * @return the Html results for all pages except Get (result of a download)
     * @throws HttpIncorrectRequestException
     */
    public String getHtmlPage(AbstractHttpBusinessRequest reference)
            throws HttpIncorrectRequestException {
        if (this.getPagerole() == PageRole.HTML) {
            // No handling of variable management, use MENU instead
            String value = reference.getHeader();
            logger.debug("Debug: " + (value != null));
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getHeader());
            }
            StringBuilder builder = null;
            if (value == null) {
                builder = new StringBuilder();
            } else {
                builder = new StringBuilder(value);
            }
            value = reference.getBeginForm();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getBeginform());
            }
            if (value != null) {
                builder.append(value);
            }
            value = reference.getEndForm();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getEndform());
            }
            if (value != null) {
                builder.append(value);
            }
            value = reference.getFooter();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getFooter());
            }
            if (value != null) {
                builder.append(value);
            }
            return builder.toString();
        }
        boolean isForm = reference.isForm();
        String value = reference.getHeader();
        if (value == null || value.length() == 0) {
            value = getPageValue(this.getHeader());
        }
        StringBuilder builder = null;
        if (value == null) {
            builder = new StringBuilder();
        } else {
            builder = new StringBuilder(value);
        }
        LinkedHashMap<String, AbstractHttpField> requestFields = reference
                .getLinkedHashMapHttpFields();
        if (!isForm) {
            value = reference.getBeginForm();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getBeginform());
            }
            if (value != null) {
                builder.append(value);
            } else {
                builder.append("<BR><TABLE border=1><TR>");
                for (AbstractHttpField field : requestFields.values()) {
                    if (field.isFieldvisibility()) {
                        builder.append("<TH>").append(field.getFieldinfo()).append("</TH>");
                    }
                }
                builder.append("<TR>");
            }
        } else {
            value = reference.getBeginForm();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getBeginform());
            }
            if (value != null) {
                builder.append(value);
            }
        }
        boolean first = true;
        for (AbstractHttpField field : requestFields.values()) {
            if (field.isFieldvisibility()) {
                // to prevent that last will have a next field form
                if (first) {
                    first = false;
                } else {
                    value = reference.getNextFieldInForm();
                    if (value == null || value.length() == 0) {
                        value = getPageValue(this.getNextinform());
                    }
                    if (value != null) {
                        builder.append(value);
                    }
                }
                value = reference.getFieldForm(field);
                if (value == null || value.length() == 0) {
                    if (isForm) {
                        value = field.getHtmlFormField(this);
                    } else {
                        value = field.getHtmlTabField(this);
                    }
                }
                if (value != null) {
                    builder.append(value);
                }
            }
        }
        if (!isForm) {
            value = reference.getEndForm();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getEndform());
            }
            if (value != null) {
                builder.append(value);
            } else {
                builder.append("</TABLE><BR>");
            }
        } else {
            value = reference.getEndForm();
            if (value == null || value.length() == 0) {
                value = getPageValue(this.getEndform());
            }
            if (value != null) {
                builder.append(value);
            }
        }
        value = reference.getFooter();
        if (value == null || value.length() == 0) {
            value = getPageValue(this.getFooter());
        }
        if (value != null) {
            builder.append(value);
        }
        return builder.toString();
    }

    /**
     * Set the value to the field according to fieldname.
     * 
     * If the field is not registered, the field is ignored.
     * 
     * @param reference
     * @param fieldname
     * @param value
     * @param position
     * @throws HttpIncorrectRequestException
     */
    public void setValue(AbstractHttpBusinessRequest reference, String fieldname, String value,
            FieldPosition position)
            throws HttpIncorrectRequestException {
        LinkedHashMap<String, AbstractHttpField> requestFields = reference
                .getLinkedHashMapHttpFields();
        AbstractHttpField field = requestFields.get(fieldname);
        if (field != null) {
            if (field.getFieldposition() == FieldPosition.ANY || field.getFieldposition() == position) {
                field.setStringValue(value);
                if (field.isFieldtovalidate()) {
                    if (!reference.isFieldValid(field)) {
                        throw new HttpIncorrectRequestException("Field unvalid: " + fieldname);
                    }
                }
            } else {
                throw new HttpIncorrectRequestException("Invalid position: " + position +
                        " while field is supposed to be in " + field.getFieldposition());
            }
        }
    }

    /**
     * Set the value to the field according to fieldname.
     * 
     * If the field is not registered, the field is ignored.
     * 
     * @param reference
     * @param fieldname
     * @throws HttpIncorrectRequestException
     */
    public void setValue(AbstractHttpBusinessRequest reference, String fieldname,
            FileUpload fileUpload)
            throws HttpIncorrectRequestException {
        LinkedHashMap<String, AbstractHttpField> requestFields = reference
                .getLinkedHashMapHttpFields();
        AbstractHttpField field = requestFields.get(fieldname);
        if (field != null) {
            field.setFileUpload(fileUpload);
            if (field.isFieldtovalidate()) {
                if (!reference.isFieldValid(field)) {
                    throw new HttpIncorrectRequestException("Field unvalid: " + fieldname);
                }
            }
        }
    }

    /**
     * 
     * @param reference
     * @return True if the request is fully valid
     */
    public boolean isRequestValid(AbstractHttpBusinessRequest reference) {
        LinkedHashMap<String, AbstractHttpField> requestFields = reference
                .getLinkedHashMapHttpFields();
        for (AbstractHttpField field : requestFields.values()) {
            if (field.isFieldmandatory() && !field.isPresent()) {
                logger.warn("Request invalid since the following field is absent: "
                        + field.getFieldname());
                return false;
            }
        }
        return reference.isRequestValid();
    }

    /**
     * Convenient method to get the fields list
     * 
     * @param reference
     * @return the fields list from the current AbstractHttpBusinessRequest
     */
    public LinkedHashMap<String, AbstractHttpField> getFieldsForRequest(
            AbstractHttpBusinessRequest reference) {
        return reference.getLinkedHashMapHttpFields();
    }

    /**
     * Convenient method to get the value of one field
     * 
     * @param reference
     * @param fieldname
     * @return the String value
     */
    public String getValue(AbstractHttpBusinessRequest reference, String fieldname) {
        AbstractHttpField field = reference.getLinkedHashMapHttpFields().get(fieldname);
        if (field != null) {
            return field.fieldvalue;
        }
        return null;
    }

    /**
     * Convenient method to get the value of one field
     * 
     * @param reference
     * @param fieldname
     * @return the FileUpload value
     */
    public FileUpload getFileUpload(AbstractHttpBusinessRequest reference, String fieldname) {
        AbstractHttpField field = reference.getLinkedHashMapHttpFields().get(fieldname);
        if (field != null) {
            return field.fileUpload;
        }
        return null;
    }

    /**
     * Convenient method to get one field
     * 
     * @param reference
     * @param fieldname
     * @return the AbstractHttpField value
     */
    public AbstractHttpField getField(AbstractHttpBusinessRequest reference, String fieldname) {
        return reference.getLinkedHashMapHttpFields().get(fieldname);
    }

    /**
     * @return the pagename
     */
    public String getPagename() {
        return pagename;
    }

    /**
     * @param pagename the pagename to set
     */
    private void setPagename(String pagename) {
        this.pagename = pagename;
    }

    /**
     * @return the fileform
     */
    public String getFileform() {
        return fileform;
    }

    /**
     * @param fileform the fileform to set
     */
    private void setFileform(String fileform) {
        this.fileform = fileform;
    }

    /**
     * @return the header
     */
    public String getHeader() {
        return header;
    }

    /**
     * @param header the header to set
     */
    private void setHeader(String header) {
        this.header = header;
    }

    /**
     * @return the footer
     */
    public String getFooter() {
        return footer;
    }

    /**
     * @param footer the footer to set
     */
    private void setFooter(String footer) {
        this.footer = footer;
    }

    /**
     * @return the beginform
     */
    public String getBeginform() {
        return beginform;
    }

    /**
     * @param beginform the beginform to set
     */
    private void setBeginform(String beginform) {
        this.beginform = beginform;
    }

    /**
     * @return the endform
     */
    public String getEndform() {
        return endform;
    }

    /**
     * @param endform the endform to set
     */
    private void setEndform(String endform) {
        this.endform = endform;
    }

    /**
     * @return the nextinform
     */
    public String getNextinform() {
        return nextinform;
    }

    /**
     * @param nextinform the nextinform to set
     */
    private void setNextinform(String nextinform) {
        this.nextinform = nextinform;
    }

    /**
     * @return the uri
     */
    public String getUri() {
        return uri;
    }

    /**
     * @param uri the uri to set
     */
    private void setUri(String uri) {
        this.uri = uri;
    }

    /**
     * @return the pagerole
     */
    public PageRole getPagerole() {
        return pagerole;
    }

    /**
     * @param pagerole the pagerole to set
     */
    private void setPagerole(PageRole pagerole) {
        this.pagerole = pagerole;
    }

    /**
     * @return the errorpage
     */
    public String getErrorpage() {
        return errorpage;
    }

    /**
     * @param errorpage the errorpage to set
     */
    private void setErrorpage(String errorpage) {
        this.errorpage = errorpage;
    }

    /**
     * @return the classname
     */
    public String getClassname() {
        return classname;
    }

    /**
     * @param classname the classname to set
     */
    private void setClassname(String classname) {
        this.classname = classname;
    }

    /**
     * @return the fields
     */
    public LinkedHashMap<String, AbstractHttpField> getFields() {
        return fields;
    }

    /**
     * @param fields the fields to set
     */
    private void setFields(LinkedHashMap<String, AbstractHttpField> fields) {
        this.fields = fields;
    }

    /**
     * @return the httpBusinessFactory
     */
    public HttpBusinessFactory getHttpBusinessFactory() {
        return httpBusinessFactory;
    }

    /**
     * @param httpBusinessFactory the httpBusinessFactory to set
     */
    private void setHttpBusinessFactory(HttpBusinessFactory httpBusinessFactory) {
        this.httpBusinessFactory = httpBusinessFactory;
    }
}
