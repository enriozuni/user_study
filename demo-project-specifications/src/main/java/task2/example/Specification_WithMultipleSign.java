package task2.example;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

@FluentTQLSpecificationClass
public class Specification_WithMultipleSign implements FluentTQLUserInterface {

	/**
     * Source
     */
    public String sourceMethodSign = "example.Main: java.lang.String source (java.lang.String[])";
    public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(0)
            .configure();
    
    
    
    
    /**
     * Sink 1
     */
    public String sinkMethodSign1 = "example.Main: void sink (java.lang.String)";
    public Method sinkMethod1 = new MethodConfigurator(sinkMethodSign1)
            .in().param(0)
            .configure();
    
    /**
     * Sink 2
     */
    public String sinkMethodSign2 = "example.Main: void sink (java.lang.String , java.lang.String)";
    public Method sinkMethod2 = new MethodConfigurator(sinkMethodSign2)
            .in().param(0)
            .configure();
    
    /**
     * Sink 3
     */
    public String sinkMethodSign3 = "example.Main: void sink (java.lang.String , java.lang.String, int)";
    public Method sinkMethod3 = new MethodConfigurator(sinkMethodSign3)
            .in().param(0)
            .configure();
    
    /**
     * Sinks
     */
    public MethodSet sinks = new MethodSet("sinks")
    		.addMethod(sinkMethod1)
    		.addMethod(sinkMethod2)
    		.addMethod(sinkMethod3);
	
    
    
    /**
     * Taint query specification
     * 
     * @return Internal FluentTQL specifications
     */
	@Override
	public List<FluentTQLSpecification> getFluentTQLSpecification() {
		TaintFlowQuery myTF = new TaintFlowQueryBuilder("Example_Specification_WithMuplitpleSign")
                .from(sourceMethod)
                .to(sinks)
                .report("There is a possible taint flow from source to the sink method.")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
	}

}
