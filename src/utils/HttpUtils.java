package utils;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import java.util.List;

public class HttpUtils {
    public static String getHeaderValue(HttpResponse response, String headerName) {
        return response.headerValue(headerName);
    }

    public static List<HttpHeader> getResponseHeaders(HttpResponse response) {
        return response.headers();
    }
}
