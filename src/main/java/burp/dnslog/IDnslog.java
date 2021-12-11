package burp.dnslog;

import com.alibaba.fastjson.JSONObject;

public interface IDnslog {
    String getName();

    String getNewDomain();

    boolean CheckResult(JSONObject respStr);

    boolean getState();

    JSONObject getPassms();
}