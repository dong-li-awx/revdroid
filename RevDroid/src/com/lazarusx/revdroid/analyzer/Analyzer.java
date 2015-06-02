package com.lazarusx.revdroid.analyzer;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import soot.MethodOrMethodContext;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.cfg.LibraryClassPatcher;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.util.InterproceduralConstantValuePropagator;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.jimple.toolkits.scalar.ConditionalBranchFolder;
import soot.jimple.toolkits.scalar.ConstantPropagatorAndFolder;
import soot.jimple.toolkits.scalar.DeadAssignmentEliminator;
import soot.jimple.toolkits.scalar.UnreachableCodeEliminator;
import soot.options.Options;
import soot.util.queue.QueueReader;

public class Analyzer {
	Application app;

	public Analyzer(Application app) {
		this.app = app;
	}

	public void analyze() {
		initSoot();

		// We explicitly select the packs we want to run for performance reasons
		PackManager.v().getPack("wjpp").apply();
		PackManager.v().getPack("cg").apply();

		eliminateDeadCode();
		 
		checkMethods();
	}

	private void initSoot() {
		soot.G.reset();

		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		// TODO: change this when necessary
		Options.v().set_output_format(Options.output_format_none);
		Options.v().set_soot_classpath(
				appendClasspath(this.app.getApkPath(),
						this.app.getAndroidJarPath()));
		Options.v().setPhaseOption("cg.spark", "on");
		Options.v().setPhaseOption("cg.spark", "string-constants:true");
		Options.v().set_whole_program(true);
		Options.v().setPhaseOption("cg", "trim-clinit:false");
		Options.v().setPhaseOption("jb.ulp", "off");
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_android_jars(this.app.getAndroidPlatformPath());

		Collection<String> classes = this.app.getEntryPointCreator()
				.getRequiredClasses();
		for (String className : classes) {
			Scene.v().addBasicClass(className, SootClass.BODIES);
		}
		Scene.v().loadNecessaryClasses();

		boolean hasClasses = false;
		for (String className : classes) {
			SootClass sootClass = Scene.v().forceResolve(className,
					SootClass.BODIES);
			if (sootClass != null) {
				sootClass.setApplicationClass();
				if (!sootClass.isPhantomClass() && !sootClass.isPhantom()) {
					hasClasses = true;
				}
			}
		}

		if (!hasClasses) {
			System.err
					.println("Only phantom classes loaded, skipping analysis...");
			return;
		}
		
		Scene.v().setEntryPoints(
				Collections.singletonList(this.app.getDummyMainMethod()));
		
		LibraryClassPatcher patcher = new LibraryClassPatcher();
		patcher.patchLibraries();
	}

	private String appendClasspath(String appPath, String libPath) {
		String s = (appPath != null && !appPath.isEmpty()) ? appPath : "";

		if (libPath != null && !libPath.isEmpty()) {
			if (!s.isEmpty())
				s += File.pathSeparator;
			s += libPath;
		}
		return s;
	}
	
	/**
	 * Performs an interprocedural dead-code elimination on all application
	 * classes
	 * @param sourcesSinks The SourceSinkManager to make sure that sources
	 * remain intact during constant propagation
	 */
	private void eliminateDeadCode() {
		// Perform an intra-procedural constant propagation to prepare for the
		// inter-procedural one
		for (QueueReader<MethodOrMethodContext> rdr =
				Scene.v().getReachableMethods().listener(); rdr.hasNext(); ) {
			MethodOrMethodContext sm = rdr.next();
			if (sm.method() == null || !sm.method().hasActiveBody())
				continue;
			
			// Exclude the dummy main method
			if (Scene.v().getEntryPoints().contains(sm.method()))
				continue;
			
			List<Unit> callSites = getCallsInMethod(sm.method());
			
			ConstantPropagatorAndFolder.v().transform(sm.method().getActiveBody());
			DeadAssignmentEliminator.v().transform(sm.method().getActiveBody());
			
			// Remove the dead callgraph edges
			List<Unit> newCallSites = getCallsInMethod(sm.method());
			if (callSites != null)
				for (Unit u : callSites)
					if (newCallSites == null ||  !newCallSites.contains(u))
						Scene.v().getCallGraph().removeAllEdgesOutOf(u);
		}
		
		// Perform an inter-procedural constant propagation and code cleanup
		// TODO: problematic here
		InterproceduralConstantValuePropagator ipcvp =
				new InterproceduralConstantValuePropagator(
						new InfoflowCFG(),
						Scene.v().getEntryPoints(),
						null,
						null);
		ipcvp.setRemoveSideEffectFreeMethods(true);
		ipcvp.transform();
		
		// Get rid of all dead code
		for (QueueReader<MethodOrMethodContext> rdr =
				Scene.v().getReachableMethods().listener(); rdr.hasNext(); ) {
			MethodOrMethodContext sm = rdr.next();
			
			if (sm.method() == null || !sm.method().hasActiveBody())
				continue;
			if (SystemClassHandler.isClassInSystemPackage(sm.method()
					.getDeclaringClass().getName()))
				continue;
			
			ConditionalBranchFolder.v().transform(sm.method().getActiveBody());
			
			// Delete all dead code. We need to be careful and patch the cfg so
			// that it does not retain edges for call statements we have deleted
			List<Unit> callSites = getCallsInMethod(sm.method());
			UnreachableCodeEliminator.v().transform(sm.method().getActiveBody());
			List<Unit> newCallSites = getCallsInMethod(sm.method());
			if (callSites != null)
				for (Unit u : callSites)
					if (newCallSites == null ||  !newCallSites.contains(u))
						Scene.v().getCallGraph().removeAllEdgesOutOf(u);
		}
	}
	
	/**
	 * Gets a list of all units that invoke other methods in the given method
	 * @param method The method from which to get all invocations
	 * @return The list of units calling other methods in the given method if
	 * there is at least one such unit. Otherwise null.
	 */
	private List<Unit> getCallsInMethod(SootMethod method) {
		List<Unit> callSites = null;
		for (Unit u : method.getActiveBody().getUnits())
			if (((Stmt) u).containsInvokeExpr()) {
				if (callSites == null)
					callSites = new ArrayList<Unit>();
				callSites.add(u);
			}
		return callSites;
	}
	
	private void checkMethods() {
		Iterator<MethodOrMethodContext> iterator = Scene.v().getReachableMethods().listener();
		while (iterator.hasNext()) {
			SootMethod sm = iterator.next().method();
			if (sm.isConcrete()) {
				for (Unit u : sm.retrieveActiveBody().getUnits()) {
					if (u instanceof Stmt) {
						Stmt stmt = (Stmt) u;
						if (stmt.containsInvokeExpr()) {
							InvokeExpr inv = stmt.getInvokeExpr();
							if (app.getMethodsConcerned().contains(inv.getMethod().getName())) {
								System.out.println(inv.getMethod().getName() + " in " + sm.getName());
							}
						}
					}
				}
			}
		}
	}
}
