package com.lazarusx.revdroid.analyzer;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import soot.G;
import soot.MethodOrMethodContext;
import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.TrapManager;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.cfg.LibraryClassPatcher;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.infoflow.util.InterproceduralConstantValuePropagator;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.jimple.toolkits.scalar.ConditionalBranchFolder;
import soot.jimple.toolkits.scalar.ConstantPropagatorAndFolder;
import soot.jimple.toolkits.scalar.DeadAssignmentEliminator;
import soot.jimple.toolkits.scalar.UnreachableCodeEliminator;
import soot.options.Options;
import soot.util.queue.QueueReader;

public class Analyzer {
	Application app;
	HashSet<Stmt> misusages = new HashSet<Stmt>();

	public Analyzer(Application app) {
		this.app = app;
	}

	public void analyze() {
		initSoot();

		// We explicitly select the packs we want to run for performance reasons
		PackManager.v().getPack("wjpp").apply();
		PackManager.v().getPack("cg").apply();

		eliminateDeadCode();
		
		patchLibraries();
		 
		findExceptionHandler(this.misusages);
	}

	private void initSoot() {
		G.reset();
		
		Main.setOutput();
		
//		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_format(Options.output_format_none);
		Options.v().set_whole_program(true);
		Options.v().set_process_dir(Collections.singletonList(this.app.getApkPath()));
//		Options.v().set_soot_classpath(
//				appendClasspath(this.app.getApkPath(),
//						"/usr/lib/jvm/java-7-oracle/jre/lib/rt.jar"));
		Options.v().set_soot_classpath(this.app.getAndroidJarPath());
		Options.v().set_android_jars(this.app.getAndroidPlatformPath());
		Options.v().set_src_prec(Options.src_prec_apk);
		soot.Main.v().autoSetOptions();

		Options.v().setPhaseOption("cg.spark", "on");
//		Options.v().setPhaseOption("cg.spark", "string-constants:true");
//		Options.v().setPhaseOption("cg", "trim-clinit:false");
//		Options.v().setPhaseOption("jb.ulp", "off");
		
//		Collection<String> classes = this.app.getEntryPointCreator()
//				.getRequiredClasses();
//		for (String className : classes) {
//			Scene.v().addBasicClass(className, SootClass.BODIES);
//		}
		Scene.v().loadNecessaryClasses();
		
		SootMethod dummyMainMethod = this.app.getEntryPointCreator().createDummyMain();
		Options.v().set_main_class(dummyMainMethod.getSignature());
		Scene.v().setEntryPoints(Collections.singletonList(dummyMainMethod));
		Scene.v().addBasicClass("java.lang.SecurityException");
//		if (Scene.v().containsClass(this.app.getDummyMainMethod().getDeclaringClass().getName()))
//			Scene.v().removeClass(this.app.getDummyMainMethod().getDeclaringClass());
//		Scene.v().addClass(this.app.getDummyMainMethod().getDeclaringClass());

//		boolean hasClasses = false;
//		for (String className : classes) {
//			SootClass sootClass = Scene.v().forceResolve(className,
//					SootClass.BODIES);
//			if (sootClass != null) {
//				sootClass.setApplicationClass();
//				if (!sootClass.isPhantomClass() && !sootClass.isPhantom()) {
//					hasClasses = true;
//				}
//			}
//		}
//
//		if (!hasClasses) {
//			System.err
//					.println("Only phantom classes loaded, skipping analysis...");
//			return;
//		}
//		
//		Scene.v().setEntryPoints(
//				Collections.singletonList(this.app.getDummyMainMethod()));
//		
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
	
	private void patchLibraries() {
		LibraryClassPatcher patcher = new LibraryClassPatcher();
		patcher.patchLibraries();
	}
	
	private void findExceptionHandler(HashSet<Stmt> misusages) {
		Iterator<MethodOrMethodContext> iterator = Scene.v().getReachableMethods().listener();
		while (iterator.hasNext()) {
			SootMethod sm = iterator.next().method();
			if (sm.isConcrete()
					&& !SystemClassHandler.isClassInSystemPackage(sm.method().getDeclaringClass().getName())) {
				for (Unit u : sm.retrieveActiveBody().getUnits()) {
					if (u instanceof Stmt) {
						Stmt stmt = (Stmt) u;
						if (stmt.containsInvokeExpr()) {
							InvokeExpr inv = stmt.getInvokeExpr();
							AndroidMethod method = new AndroidMethod(inv.getMethod());
							if (app.getMethodsConcerned().contains(method)) {
								Helper.printDebugMessage("Occurrence found " + method.getSignature() + " " + sm.getSignature());
																
								HashSet<Stmt> history = new HashSet<Stmt>();
								if (checkStatement(stmt, sm, history)) {
									Helper.printDebugMessage("Found traps containing the method");
								} else {
									misusages.add(stmt);
									Helper.printDebugMessage("Not found traps containing the method");
								}
							}
						}
					}
				}
			}
		}
	}
	
	/*
	 * @param	stmt	the stmt which might lead to SecurityException
	 * @param	sm		the method which stmt belongs to
	 * @param	history	a collection of stmt's which have been checked before
	 */
	private boolean checkStatement(Stmt stmt, SootMethod sm, HashSet<Stmt> history) {
		if (history.contains(stmt)) {
			Helper.printDebugMessage("Recursion found. Not found trap in caller");
			return false;
		} else {
			history.add(stmt);
		}
		
		// Super classes of `SecurityException` are included into analysis by Soot.
		// See the source code of `TrapManager.isExceptionCaughtAt()`.
		if (TrapManager.isExceptionCaughtAt(Scene.v().getSootClass("java.lang.SecurityException"), stmt, sm.getActiveBody())) {
			return true;
		} else {
			Collection<Unit> callers = new JimpleBasedInterproceduralCFG().getCallersOf(sm);
			
			if (callers.isEmpty()) {
				return false;
			} else {
				for (Unit u : callers) {
					if (u instanceof Stmt) {
						Stmt callerStmt = (Stmt) u;
						if (!checkStatement(callerStmt, callerStmt.getInvokeExpr().getMethod(), history)) {
							System.out.println("Not found trap in caller");
							return false;
						}
					} else  {
						return false;
					}
				}
				
				System.out.println("Found trap in caller");
				return true;
			}
		}
	}
}
