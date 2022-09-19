package org.opensearch.security.filter;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.search.GetAllPitNodesRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.RolesInjector;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PitPrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.PrivilegesInterceptor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PitFilter  implements ActionFilter {

    private final ClusterService clusterService;

    private final IndexNameExpressionResolver resolver;

    private final AuditLog auditLog;
    private ThreadContext threadContext;

    private PrivilegesInterceptor privilegesInterceptor;

    private final AdminDNs adminDns;
    private final RolesInjector rolesInjector;

    private ConfigModel configModel;

    private DynamicConfigModel dcm;


    private PrivilegesEvaluator privilegesEvaluator;

    @Override
    public int order() {
        return 0;
    }

    public PitFilter(final ClusterService clusterService, final ThreadPool threadPool, final IndexNameExpressionResolver resolver,
                     AuditLog auditLog, final PrivilegesInterceptor privilegesInterceptor,  AdminDNs adminDns, PrivilegesEvaluator privilegesEvaluator, DynamicConfigModel dcm, ConfigModel configModel) {
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.privilegesInterceptor = privilegesInterceptor;

        this.adminDns = adminDns;
        this.rolesInjector = new RolesInjector(auditLog);
        this.privilegesEvaluator = privilegesEvaluator;
        this.configModel = configModel;
        this.dcm = dcm;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(Task task, String action,
                                                                                       Request request, ActionListener<Response> listener, ActionFilterChain<Request, Response> chain) {
        if(! (request instanceof GetAllPitNodesRequest)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        final TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final Set<String> injectedRoles = rolesInjector.injectUserAndRoles(request, action, task, threadContext);
        Set<String> mappedRoles = (injectedRoles == null) ? mapRoles(user, caller) : injectedRoles;

        presponse.resolvedSecurityRoles.addAll(mappedRoles);
        final SecurityRoles securityRoles = privilegesEvaluator.getSecurityRoles(mappedRoles);

        PitPrivilegesEvaluator pitPrivilegesEvaluator = new PitPrivilegesEvaluator();
        ActionListener wrappedActionListener = ActionListener.wrap(r-> {
            // check access for point in time requests
            PrivilegesEvaluatorResponse pres  = pitPrivilegesEvaluator.evaluate(request, clusterService, user, securityRoles,
                    action, resolver, dcm.isDnfofForEmptyResultsEnabled(), presponse);
            if (pres.isAllowed()) {
                listener.onResponse((Response) ((GetAllPitNodesRequest) request).getGetAllPitNodesResponse());
            }
            else {
                String err;
                if(!pres.getMissingSecurityRoles().isEmpty()) {
                    err = String.format("No mapping for %s on roles %s", user, pres.getMissingSecurityRoles());
                } else {
                    err = (injectedRoles != null) ?
                            String.format("no permissions for %s and associated roles %s", pres.getMissingPrivileges(), pres.getResolvedSecurityRoles()) :
                            String.format("no permissions for %s and %s", pres.getMissingPrivileges(), user);
                }
                listener.onFailure(new OpenSearchSecurityException(err, RestStatus.FORBIDDEN)));
            }
        }, e -> {
            listener.onFailure(e);
        });
        chain.proceed(task, action, request, wrappedActionListener);
    }

    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        if (user != null && adminDns.isAdmin(user)) {
            return true;
        }

        return false;
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }
}
