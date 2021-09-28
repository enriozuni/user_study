package task1.example;

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


@FluentTQLSpecificationClass
public class Specification_WithMethodSignature implements FluentTQLUserInterface {

    /**
     * Source
     */
    public MethodSignature sourceMethodSign = new MethodSignatureConfigurator()
            .atClass("example.Main")
            .returns("java.lang.String")
            .named("source")
            .accepts("java.lang.String[]")
            .configure();
    
    public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(0)
            .configure();

    
    /**
     * Sink
     */
    public MethodSignature sinkMethodSign = new MethodSignatureConfigurator()
    		.atClass("example.Main")
    		.returns("void")
    		.named("sink")
    		.accepts("java.lang.String")
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
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("Example_Specification_WithMethodSign")
                .from(sourceMethod)
                .to(sinkMethod)
                .report("There is a possible taint flow from source to the sink method.")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }

}
