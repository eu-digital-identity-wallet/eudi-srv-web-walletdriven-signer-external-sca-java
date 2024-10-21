package eu.europa.ec.eudi.signer.r3.sca.web.dto.credentialsInfo;

import java.util.List;

public class CredentialsInfoAuth {
    private String mode;
    private String expression;
    private List<Object> objects;

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public List<Object> getObjects() {
        return objects;
    }

    public void setObjects(List<Object> objects) {
        this.objects = objects;
    }

    @Override
    public String toString() {
        return "CredentialsInfoAuth{" +
                "mode='" + mode + '\'' +
                ", expression='" + expression + '\'' +
                ", objects=" + objects +
                '}';
    }
}
