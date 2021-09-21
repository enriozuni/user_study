package task1.exercise;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSignatureConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.MethodSignature;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
 * <p>
 * The software does not neutralize or incorrectly neutralizes user-controllable input before
 * it is placed in output that is used as a web page that is served to other users.
 */
@FluentTQLSpecificationClass
public class Specification_WithMethodSignature implements FluentTQLUserInterface {

    /**
     * Source
     */
	// ToDo: specify the method signature for the source
	public MethodSignature sourceMethodSign;
	
    public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(0)
            .configure();

    
    

    /**
     * Sanitizer
     */
    public MethodSignature sanitizerMethodSign = new MethodSignatureConfigurator()
    		.atClass("de.fraunhofer.iem.secucheck.todolist.controllers.LoginController")
    		.returns("de.fraunhofer.iem.secucheck.todolist.model.User")
    		.named("NameIt")
    		.accepts("de.fraunhofer.iem.secucheck.todolist.model.User")
    		.configure();
    
    public Method sanitizerMethod = new MethodConfigurator(sanitizerMethodSign)
            .in().param(0)
            .out().returnValue()
            .configure();


    
    
    /**
     * Sink
     */
    public MethodSignature sinkMethodSign = new MethodSignatureConfigurator()
            .atClass("de.fraunhofer.iem.secucheck.todolist.service.UserService")
            .returns("void")
            .named("saveUserDefault")
            .accepts("de.fraunhofer.iem.secucheck.todolist.model.User")
            .configure();
    
    public Method sinkMethod = new MethodConfigurator(sinkMethodSign)
            .in().param(0)
            .configure();

    
    
    
    /**
     * Taint query specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE79_CrossSiteScripting_WithMethodSign")
                .from(sourceMethod)
                .to(sinkMethod)
                .report("CWE-79 detected: Cross-site Scripting from untrusted value 'String pattern'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }

}
