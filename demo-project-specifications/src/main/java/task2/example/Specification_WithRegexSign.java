package task2.example;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

@FluentTQLSpecificationClass
public class Specification_WithRegexSign implements FluentTQLUserInterface {

	/**
     * Source
     */
    public String sourceMethodSign = "example.Main: java.lang.String source (java.lang.String[])";
    public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(0)
            .configure();
    
    
    /**
     * Sinks
     */
    public String sinkMethodSign = "example.Main: void sink ( ANY )";
    public Method sinkMethod = new MethodConfigurator(sinkMethodSign)
            .in().param(0)
            .configure();
	
    
    
    /**
     * Taint query specification
     * 
     * @return Internal FluentTQL specifications
     */
	@Override
	public List<FluentTQLSpecification> getFluentTQLSpecification() {
		TaintFlowQuery myTF = new TaintFlowQueryBuilder("Example_Specification_WithRegexSign")
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
