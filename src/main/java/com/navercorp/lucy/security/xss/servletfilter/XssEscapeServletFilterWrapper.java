/*
 * Copyright 2014 NAVER Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.navercorp.lucy.security.xss.servletfilter;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.Part;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * @author todtod80
 * @author leeplay
 */
public class XssEscapeServletFilterWrapper extends HttpServletRequestWrapper {

	private static final Log LOG = LogFactory.getLog(XssEscapeServletFilterWrapper.class);

	private final XssEscapeFilter xssEscapeFilter;
	private final String path;
	private final Gson gson;
	private final boolean isMultipart;

	public XssEscapeServletFilterWrapper(ServletRequest request, XssEscapeFilter xssEscapeFilter, Gson gson) {
		super((HttpServletRequest) request);

		isMultipart = isMultipartContent((HttpServletRequest) request);

		this.xssEscapeFilter = xssEscapeFilter;
		this.gson = gson;

		String contextPath = ((HttpServletRequest) request).getContextPath();
		this.path = ((HttpServletRequest) request).getRequestURI().substring(contextPath.length());
	}


	@Override
	public Part getPart(String name) throws IOException, ServletException {
		Part part = super.getPart(name);
		if (part == null) {
			return null;
		}
		return new XssFilteredPart(part);
	}

	@Override
	public String getParameter(String paramName) {
		String value = super.getParameter(paramName);
		return doFilter(paramName, value);
	}

	@Override
	public String[] getParameterValues(String paramName) {
		String[] values = super.getParameterValues(paramName);
		if (values == null) {
			return null;
		}
		for (int index = 0; index < values.length; index++) {
			values[index] = doFilter(paramName, values[index]);
		}
		return values;
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		Map<String, String[]> paramMap = super.getParameterMap();
		Map<String, String[]> newFilteredParamMap = new HashMap<>();

		Set<Map.Entry<String, String[]>> entries = paramMap.entrySet();
		for (Map.Entry<String, String[]> entry : entries) {
			String paramName = entry.getKey();
			Object[] valueObj = entry.getValue();
			String[] filteredValue = new String[valueObj.length];
			for (int index = 0; index < valueObj.length; index++) {
				filteredValue[index] = doFilter(paramName, String.valueOf(valueObj[index]));
			}

			newFilteredParamMap.put(entry.getKey(), filteredValue);
		}

		return newFilteredParamMap;
	}

	@Override
	public ServletInputStream getInputStream() {
		try {
			if (isMultipart) {
				return super.getInputStream();
			}
			return getEscapedInputStream(super.getInputStream());
		} catch (IOException | JsonParseException ioe) {
			LOG.error("get escapedInputStream Exception", ioe);
		}

		return getInputStream();
	}

	/**
	 * @param paramName String
	 * @param value     String
	 * @return String
	 */
	private String doFilter(String paramName, String value) {
		return xssEscapeFilter.doFilter(path, paramName, value);
	}

	private boolean isMultipartContent(HttpServletRequest request) {
		return Objects.equals("multipart/form-data", request.getContentType().toLowerCase());
	}

	private ServletInputStream getEscapedInputStream(InputStream originalInputStream) throws IOException {
		String inputString = IOUtils.toString(originalInputStream, getCharacterEncoding());
		Map<String, Object> map = gson.fromJson(inputString, Map.class);
		Set<String> keys = map.keySet();
		for (String key : keys) {
			Object value = map.get(key);
			if (value instanceof String) {
				map.put(key, doFilter(key, (String) map.get(key)));
			}
		}
		String result = gson.toJson(map);

		return new XssFilteredServletInputStream(new ByteArrayInputStream(result.getBytes(getCharacterEncoding())));
	}

	public class XssFilteredPart implements Part {

		private final Part originalPart;

		private XssFilteredPart(Part originalPart) {
			this.originalPart = originalPart;
		}

		@Override
		public InputStream getInputStream() throws IOException {
			if (Objects.equals("application/json", originalPart.getContentType().toLowerCase())) {
				return getEscapedInputStream(originalPart.getInputStream());
			}
			return originalPart.getInputStream();
		}

		@Override
		public String getContentType() {
			return originalPart.getContentType();
		}

		@Override
		public String getName() {
			return originalPart.getName();
		}

		@Override
		public String getSubmittedFileName() {
			return originalPart.getSubmittedFileName();
		}

		@Override
		public long getSize() {
			return originalPart.getSize();
		}

		@Override
		public void write(String fileName) throws IOException {
			originalPart.write(fileName);
		}

		@Override
		public void delete() throws IOException {
			originalPart.delete();
		}

		@Override
		public String getHeader(String name) {
			return originalPart.getHeader(name);
		}

		@Override
		public Collection<String> getHeaders(String name) {
			return originalPart.getHeaders(name);
		}

		@Override
		public Collection<String> getHeaderNames() {
			return originalPart.getHeaderNames();
		}
	}

	public static class XssFilteredServletInputStream extends ServletInputStream {
		private final ByteArrayInputStream input;

		public XssFilteredServletInputStream(ByteArrayInputStream input) {
			this.input = input;
		}


		@Override
		public int read() {
			return input.read();
		}

		@Override
		public boolean isFinished() {
			return false;
		}

		@Override
		public boolean isReady() {
			return false;
		}

		@Override
		public void setReadListener(ReadListener listener) {

		}
	}
}
