package task1.example;

import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CONSTANTS.LOCATION;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodConfigurator;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.TaintFlowQueryBuilder;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.annotations.FluentTQLSpecificationClass;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.FluentTQLSpecification;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
 * <p>
 * The software uses external input to construct a pathname that is intended to identify
 * a file or directory that is located underneath a restricted parent directory,
 * but the software does not properly neutralize special elements within the pathname
 * that can cause the pathname to resolve to a location that is outside of the restricted directory.
 */
@FluentTQLSpecificationClass
public class Specification_WithString implements FluentTQLUserInterface {

    /**
     * Source
     */
	public String sourceMethodSign = "de.fraunhofer.iem.secucheck.todolist.controllers.NewTaskController: "
			+ "java.lang.String "
			+ "saveTask "
			+ "(de.fraunhofer.iem.secucheck.todolist.model.Task , "
			+ "org.springframework.web.multipart.MultipartFile , "
			+ "org.springframework.web.servlet.mvc.support.RedirectAttributes)";
    
	public Method sourceMethod = new MethodConfigurator(sourceMethodSign)
            .out().param(0)
            .configure();

	
	
    /**
     * Sanitizer
     */
	public String sanitizerMethodSign = "de.fraunhofer.iem.secucheck.todolist.controllers.NewTaskController: "
			+ "java.lang.String "
			+ "correctFileName "
			+ "(java.lang.String)";
	
    public Method sanitizerMethod = new MethodConfigurator(sanitizerMethodSign)
            .in().param(0)
            .out().returnValue()
            .configure();

    
    
    /**
     * Sink
     */
    public String sinkMethodSign = "de.fraunhofer.iem.secucheck.todolist.service.DirectoryStorageService: "
    		+ "java.lang.String "
    		+ "store "
    		+ "(org.springframework.web.multipart.MultipartFile , "
    		+ "de.fraunhofer.iem.secucheck.todolist.model.Task , "
    		+ "java.lang.String)";
    
    public Method sinkMethod = new MethodConfigurator(sinkMethodSign)
            .in().param(1)
            .configure();

    
    
    /**
     * Taint query specification
     *
     * @return Internal FluentTQL specifications
     */
    public List<FluentTQLSpecification> getFluentTQLSpecification() {
        TaintFlowQuery myTF = new TaintFlowQueryBuilder("CWE22_PathTraversal")
                .from(sourceMethod)
                .notThrough(sanitizerMethod)
                .to(sinkMethod)
                .report("CWE-22 detected: Path Traversal from untrusted value 'Task newTask'")
                .at(LOCATION.SOURCEANDSINK)
                .build();

        List<FluentTQLSpecification> myFluentTQLSpecs = new ArrayList<FluentTQLSpecification>();
        myFluentTQLSpecs.add(myTF);

        return myFluentTQLSpecs;
    }

}
