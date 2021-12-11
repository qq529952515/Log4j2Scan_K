package burp.dnslog.platform;

import burp.dnslog.IDnslog;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static burp.utils.HttpUtils.GetDefaultRequest;

public class LogXn implements IDnslog {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(10, TimeUnit.SECONDS).
            callTimeout(10, TimeUnit.SECONDS).build();
            JSONObject paraMss = null;
            String platformUrl = "https://log.xn--9tr.com/";
            String rootDomain = "";

    public LogXn() {
        this.initDomain();
    }
    private void initDomain() {
        try {
            Response resp = client.newCall(GetDefaultRequest("https://log.xn--9tr.com/new_gen?t=0.3113540327207853").build()).execute();
            String respStr = resp.body().string();
            paraMss = Utils.sloveJSON(respStr);
            String domain_v1 = paraMss.getString("domain");
            rootDomain = domain_v1.substring(0,domain_v1.length()-1);
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }
    public JSONObject getPassms(){return paraMss;}

    @Override
    public String getName() {
        return "log.xn--9tr.com";
    }

    @Override
    public String getNewDomain() {
        //return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
        return Utils.GetRandomString(5) + "." + rootDomain;
    }

    @Override
    public  boolean CheckResult(JSONObject respStr){
        try {
            String domain = respStr.getString("domain");
            String token  = respStr.getString("token");
            Response resp = client.newCall(HttpUtils.GetDefaultRequestNew(domain,token,platformUrl + token + "?t=0.3113540327207853").build()).execute();
            String  responsedata = resp.body().string();
            System.out.println(responsedata);
            return responsedata.contains("subdomain");
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
    }

    @Override
    public boolean getState() {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl).build()).execute();
            return resp.code() == 200;
        } catch (Exception ex) {
            return false;
        }
    }
}