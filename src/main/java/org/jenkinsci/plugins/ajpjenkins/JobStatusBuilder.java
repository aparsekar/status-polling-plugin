package org.jenkinsci.plugins.ajpjenkins;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.Launcher;
import hudson.model.*;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.ServletException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Sample {@link Builder}.
 * <p/>
 * <p/>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked
 * and a new {@link JobStatusBuilder} is created. The created
 * instance is persisted to the project configuration XML by using
 * XStream, so this allows you to use instance fields (like {@link #name})
 * to remember the configuration.
 * <p/>
 * <p/>
 * When a build is performed, the {@link #perform(AbstractBuild, Launcher, BuildListener)}
 * method will be invoked.
 *
 */
public class JobStatusBuilder extends Builder {
    private final String credentialsId;
    private final String urlEndPoint;
    private final Integer pollingInterval;
    private transient StandardUsernameCredentials credentials;

    @DataBoundConstructor
    public JobStatusBuilder(String urlEndPoint, Integer pollingInterval, String credentialsId) {
        this.urlEndPoint = urlEndPoint;
        this.pollingInterval = pollingInterval;
        this.credentialsId = credentialsId;
    }

    public String getUrlEndPoint() {
        return urlEndPoint;
    }

    public Integer getPollingInterval() {
        return pollingInterval;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public StandardUsernameCredentials getCredentials() {
        String credentialsId = (this.credentialsId == null) ? (this.credentials == null ? null : this.credentials.getId()) : this.credentialsId;
        try {
            StandardUsernameCredentials credentials = CredentialsMatchers.firstOrNull(
                    CredentialsProvider
                            .lookupCredentials(StandardUsernameCredentials.class, Jenkins.getInstance(), ACL.SYSTEM, null, null),
                    CredentialsMatchers.withId(credentialsId)
            );
            if (credentials != null) {
                this.credentials = credentials;
                return credentials;
            }
        } catch (Throwable t) {
            // ignore
        }
        return this.credentials;
    }
    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
        PrintStream logger = listener.getLogger();
        try {
            logger.println(urlEndPoint);
            String protocol = "http";
            if (urlEndPoint.startsWith("https")) {
                protocol = "https";
            }
            StandardUsernameCredentials standardUsernameCredentials = getCredentials();
            String user = standardUsernameCredentials.getUsername();
            String pass = ((UsernamePasswordCredentialsImpl) standardUsernameCredentials).getPassword().getPlainText();
            HttpURLConnection urlConnection;
            URL endPointUrl = new URL(urlEndPoint);
            String authString = user + ":" + pass;
            String authStringEnc = new String(Base64.encodeBase64(authString.getBytes()));
            for (boolean countinue_polling = true; countinue_polling; ) {
                Thread.sleep(pollingInterval);
                if ("https".equalsIgnoreCase(protocol)) {
                    urlConnection = (HttpsURLConnection) endPointUrl.openConnection();
                } else {
                    urlConnection = (HttpURLConnection) endPointUrl.openConnection();
                }
                urlConnection.setRequestProperty("Authorization", "Basic " + authStringEnc);
                logger.println("URL : " + urlEndPoint);
                logger.println("Basic Auth Header: " + authStringEnc);
                urlConnection.setRequestProperty("User-Agent", "Mozilla/5.0");
                int responseCode = urlConnection.getResponseCode();
                BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                switch (responseCode) {
                    case 202:
                        logger.println("Continue->  code: " + responseCode + "\n" + response.toString());
                        countinue_polling = true;
                        break;

                    case 200:
                        logger.println("Success-> code: " + responseCode + "\n" + response.toString());
                        return true;

                    default:
                        logger.println("Failure-> code: " + responseCode + "\n" + response.toString());
                        return false;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("JobStatusPolling Exception.", e);
        }
        return false;
    }

    /**
     * Descriptor for {@link JobStatusBuilder}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     * <p/>
     * <p/>
     * See <tt>src/main/resources/hudson/plugins/hello_world/HelloWorldBuilder/*.jelly</tt>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        /**
         * In order to load the persisted global configuration, you have to
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            load();
        }

        /**
         * Performs on-the-fly validation of the form field 'urlEndPoint'.
         *
         * @param value This parameter receives the value that the user has typed.
         * @return Indicates the outcome of the validation. This is sent to the browser.
         * <p/>
         */
        public FormValidation doCheckUrlEndPoint(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0) {
                return FormValidation.error("Please set a Url end point");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckCredentialsId(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0) {
                return FormValidation.error("Please set Credentials");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckPollingInterval(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0) {
                return FormValidation.error("Please set Polling interval");
            }
            return FormValidation.ok();
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath ItemGroup context) {
            if (!(context instanceof AccessControlled ? (AccessControlled) context : Jenkins.getInstance()).hasPermission(Computer.CONFIGURE)) {
                return new ListBoxModel();
            }
            return new StandardUsernameListBoxModel().withMatching(new CredentialsMatcher() {
                @Override
                public boolean matches(Credentials item) {
                    return item instanceof UsernamePasswordCredentialsImpl;
                }
            }, CredentialsProvider.lookupCredentials(StandardUsernameCredentials.class, context, ACL.SYSTEM, null, null));
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Status Polling";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            save();
            return super.configure(req, formData);
        }
    }
}

