package com.lazarusx.revdroid.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.xmlpull.v1.XmlPullParserException;

import soot.Main;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.IInfoflow.CallgraphAlgorithm;
import soot.jimple.infoflow.android.AnalyzeJimpleClass;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.resources.ARSCFileParser;
import soot.jimple.infoflow.android.resources.LayoutControl;
import soot.jimple.infoflow.android.resources.ARSCFileParser.AbstractResource;
import soot.jimple.infoflow.android.resources.ARSCFileParser.ResPackage;
import soot.jimple.infoflow.android.resources.ARSCFileParser.StringResource;
import soot.jimple.infoflow.android.resources.LayoutFileParser;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.entryPointCreators.AndroidEntryPointCreator;
import soot.options.Options;

public class Application {
	private String apkPath;
	private String pscoutResultPath;
	private String androidPlatformPath;
	private String androidJarPath;
	private String packageName;
	private String appName;
	private Set<String> permissions;
	private Set<String> entryPoints;
	private SootMethod dummyMainMethod;
	private ArrayList<AndroidMethod> methodsConcerned;
	private List<ResPackage> resourcePackages;
	private Map<String, Set<SootMethodAndClass>> callbackMethods;
	private AndroidEntryPointCreator entryPointCreator;
	private CallgraphAlgorithm callgraphAlgorithm = CallgraphAlgorithm.AutomaticSelection;

	public Application(String androidPlatformPath, String apkPath,
			String pscoutResultPath) throws IOException, XmlPullParserException {
		this.androidPlatformPath = androidPlatformPath;
		this.apkPath = apkPath;
		this.pscoutResultPath = pscoutResultPath;
		this.callbackMethods = new HashMap<String, Set<SootMethodAndClass>>();
		
		// Get metadata including:
		// - package name
		// - app name
		// - permissions
		// - entry points, i.e., activity classes, service classes, etc.
		calculateMetadata();
		
		// Get a list of methods which we are concerned
		// according to the permissions which the application
		// requests and PScout result
		calculateMethodsConcernedFromPScoutResult();
		
		// Calculate resource packages, callback methods
		// and dummy main method
		calculateResourcePackagesAndCallbackMethods();
		
		// Calculate the entry point creator and dummy main method 
		calculateDummyMainMethod();
	}
	
	public String getApkPath() {
		return apkPath;
	}
	
	public String getAndroidPlatformPath() {
		return androidPlatformPath;
	}
	
	public String getAndroidJarPath() {
		return androidJarPath;
	}

	public String getPackageName() {
		return packageName;
	}

	public String getAppName() {
		return appName;
	}

	public Set<String> getPermissions() {
		return permissions;
	}

	public Set<String> getEntryPoints() {
		return entryPoints;
	}

	public List<ResPackage> getResourcePackages() {
		return resourcePackages;
	}

	public Map<String, Set<SootMethodAndClass>> getCallbackMethods() {
		return callbackMethods;
	}

	public CallgraphAlgorithm getCallgraphAlgorithm() {
		return callgraphAlgorithm;
	}

	public SootMethod getDummyMainMethod() {
		return dummyMainMethod;
	}
	
	public ArrayList<AndroidMethod> getMethodsConcerned() {
		return this.methodsConcerned;
	}
	
	public AndroidEntryPointCreator getEntryPointCreator() {
		return entryPointCreator;
	}

	public void setCallgraphAlgorithm(CallgraphAlgorithm callgraphAlgorithm) {
		this.callgraphAlgorithm = callgraphAlgorithm;
	}

	// For debug purpose
	public void printEntryPoints() {
		if (this.entryPoints == null) {
			System.out.println("Entry points not initialized");
		} else {
			System.out.println("Classes containing entry points:");
			for (String className : entryPoints)
				System.out.println("\t" + className);
			System.out.println("End of entry points");
		}
	}

	// For debug purpose
	public void printMethodsConcerned() {
		if (this.methodsConcerned == null) {
			System.out.println("Methods concerned not initialized");
		} else {
			System.out.println("Methods concerned: ");
			for (AndroidMethod method : this.methodsConcerned) {
				System.out.println("\t" + method);
			}
			System.out.println("End of methods concerned");
		}
	}

	private void calculateMetadata() throws IOException, XmlPullParserException {
		this.androidJarPath = Scene.v().getAndroidJarPath(this.androidPlatformPath,
				this.apkPath);
		ProcessManifest processManifest = new ProcessManifest(this.apkPath);
		this.packageName = processManifest.getPackageName();
		this.appName = processManifest.getApplicationName();
		this.permissions = processManifest.getPermissions();
		this.entryPoints = processManifest.getEntryPointClasses();
		processManifest.close();
	}

	private void calculateMethodsConcernedFromPScoutResult() throws IOException {
		PScoutParser parser = PScoutParser.fromFile(this.pscoutResultPath);
		this.methodsConcerned = parser.parse(this.permissions);
	}

	// Actually I didn't know what the hell is `resource packages'
	private void calculateResourcePackagesAndCallbackMethods() throws IOException {
		ARSCFileParser resParser = new ARSCFileParser();
		resParser.parse(this.apkPath);
		this.resourcePackages = resParser.getPackages();

		LayoutFileParser lfp = new LayoutFileParser(this.packageName, resParser);
		calculateCallbackMethods(resParser, lfp);
	}

	private void calculateDummyMainMethod() {
		soot.G.reset();
		initSoot();
		this.entryPointCreator = createEntryPointCreator();
		this.dummyMainMethod = this.entryPointCreator.createDummyMain();
	}

	/**
	 * Calculates the set of callback methods declared in the XML resource files
	 * or the app's source code
	 * 
	 * @param resParser
	 *            The binary resource parser containing the app resources
	 * @param lfp
	 *            The layout file parser to be used for analyzing UI controls
	 * @throws IOException
	 *             Thrown if a required configuration cannot be read
	 */
	private void calculateCallbackMethods(ARSCFileParser resParser,
			LayoutFileParser lfp) throws IOException {
		AnalyzeJimpleClass jimpleClass = null;

		boolean hasChanged = true;
		while (hasChanged) {
			hasChanged = false;

			// Create the new iteration of the main method
			soot.G.reset();
			initSoot();
			createMainMethodAndAddToSoot();

			if (jimpleClass == null) {
				// Collect the callback interfaces implemented in the app's
				// source code
				jimpleClass = new AnalyzeJimpleClass(this.entryPoints);
				jimpleClass.collectCallbackMethods();

				// Find the user-defined sources in the layout XML files. This
				// only needs to be done once, but is a Soot phase.
				lfp.parseLayoutFile(this.apkPath, this.entryPoints);
			} else
				jimpleClass.collectCallbackMethodsIncremental();

			// Run the soot-based operations
			PackManager.v().getPack("wjpp").apply();
			PackManager.v().getPack("cg").apply();
			PackManager.v().getPack("wjtp").apply();

			// Collect the results of the soot-based phases
			for (Entry<String, Set<SootMethodAndClass>> entry : jimpleClass
					.getCallbackMethods().entrySet()) {
				if (this.callbackMethods.containsKey(entry.getKey())) {
					if (this.callbackMethods.get(entry.getKey()).addAll(
							entry.getValue()))
						hasChanged = true;
				} else {
					this.callbackMethods.put(entry.getKey(), new HashSet<>(
							entry.getValue()));
					hasChanged = true;
				}
			}
		}

		// Collect the XML-based callback methods
		for (Entry<String, Set<Integer>> lcentry : jimpleClass
				.getLayoutClasses().entrySet()) {
			final SootClass callbackClass = Scene.v().getSootClass(
					lcentry.getKey());

			for (Integer classId : lcentry.getValue()) {
				AbstractResource resource = resParser.findResource(classId);
				if (resource instanceof StringResource) {
					final String layoutFileName = ((StringResource) resource)
							.getValue();

					// Add the callback methods for the given class
					Set<String> callbackMethods = lfp.getCallbackMethods().get(
							layoutFileName);
					if (callbackMethods != null) {
						for (String methodName : callbackMethods) {
							final String subSig = "void " + methodName
									+ "(android.view.View)";

							// The callback may be declared directly in the
							// class
							// or in one of the superclasses
							SootClass currentClass = callbackClass;
							while (true) {
								SootMethod callbackMethod = currentClass
										.getMethodUnsafe(subSig);
								if (callbackMethod != null) {
									addCallbackMethod(callbackClass.getName(),
											new AndroidMethod(callbackMethod));
									break;
								}
								if (!currentClass.hasSuperclass()) {
									System.err.println("Callback method "
											+ methodName
											+ " not found in class "
											+ callbackClass.getName());
									break;
								}
								currentClass = currentClass.getSuperclass();
							}
						}
					}

					// For user-defined views, we need to emulate their
					// callbacks
					Set<LayoutControl> controls = lfp.getUserControls().get(
							layoutFileName);
					if (controls != null)
						for (LayoutControl lc : controls)
							registerCallbackMethodsForView(callbackClass, lc);
				} else
					System.err
							.println("Unexpected resource type for layout class");
			}
		}

		// Add the callback methods as sources and sinks
//		Set<SootMethodAndClass> callbacksPlain = new HashSet<SootMethodAndClass>();
//		for (Set<SootMethodAndClass> set : this.callbackMethods.values()) {
//			callbacksPlain.addAll(set);
//		}
	}

	/**
	 * Initializes soot for running the soot-based phases of the application
	 * callback calculation
	 */
	private void initSoot() {
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_format(Options.output_format_none);
		Options.v().set_whole_program(true);
		Options.v().set_process_dir(Collections.singletonList(this.apkPath));
		Options.v().set_soot_classpath(this.androidJarPath);
		Options.v().set_android_jars(this.androidPlatformPath);
		Options.v().set_src_prec(Options.src_prec_apk);
		Main.v().autoSetOptions();

		// Configure the callgraph algorithm
		switch (callgraphAlgorithm) {
		case AutomaticSelection:
			Options.v().setPhaseOption("cg.spark", "on");
			break;
		case RTA:
			Options.v().setPhaseOption("cg.spark", "on");
			Options.v().setPhaseOption("cg.spark", "rta:true");
			break;
		case VTA:
			Options.v().setPhaseOption("cg.spark", "on");
			Options.v().setPhaseOption("cg.spark", "vta:true");
			break;
		default:
			throw new RuntimeException("Invalid callgraph algorithm");
		}

		// Load whatever we need
		Scene.v().loadNecessaryClasses();
	}

	/**
	 * Creates the main method based on the current callback information,
	 * injects it into the Soot scene.
	 */
	private void createMainMethodAndAddToSoot() {
		// Always update the entry point creator to reflect the newest set
		// of callback methods
		this.dummyMainMethod = createEntryPointCreator().createDummyMain();
		Scene.v().setEntryPoints(Collections.singletonList(this.dummyMainMethod));
		if (Scene.v().containsClass(this.dummyMainMethod.getDeclaringClass().getName()))
			Scene.v().removeClass(this.dummyMainMethod.getDeclaringClass());
		Scene.v().addClass(this.dummyMainMethod.getDeclaringClass());
	}

	private AndroidEntryPointCreator createEntryPointCreator() {
		AndroidEntryPointCreator entryPointCreator = new AndroidEntryPointCreator(
				new ArrayList<String>(this.entryPoints));
		Map<String, List<String>> callbackMethodSigs = new HashMap<String, List<String>>();
		for (String className : this.callbackMethods.keySet()) {
			List<String> methodSigs = new ArrayList<String>();
			callbackMethodSigs.put(className, methodSigs);
			for (SootMethodAndClass am : this.callbackMethods.get(className))
				methodSigs.add(am.getSignature());
		}
		entryPointCreator.setCallbackFunctions(callbackMethodSigs);
		return entryPointCreator;
	}

	/**
	 * Adds a method to the set of callback method
	 * 
	 * @param layoutClass
	 *            The layout class for which to register the callback
	 * @param callbackMethod
	 *            The callback method to register
	 */
	private void addCallbackMethod(String layoutClass,
			AndroidMethod callbackMethod) {
		Set<SootMethodAndClass> methods = this.callbackMethods.get(layoutClass);
		if (methods == null) {
			methods = new HashSet<SootMethodAndClass>();
			this.callbackMethods.put(layoutClass, methods);
		}
		methods.add(new AndroidMethod(callbackMethod));
	}

	/**
	 * Registers the callback methods in the given layout control so that they
	 * are included in the dummy main method
	 * 
	 * @param callbackClass
	 *            The class with which to associate the layout callbacks
	 * @param lc
	 *            The layout control whose callbacks are to be associated with
	 *            the given class
	 */
	private void registerCallbackMethodsForView(SootClass callbackClass,
			LayoutControl lc) {
		// Ignore system classes
		if (callbackClass.getName().startsWith("android."))
			return;
		if (lc.getViewClass().getName().startsWith("android."))
			return;

		// Check whether the current class is actually a view
		{
			SootClass sc = lc.getViewClass();
			boolean isView = false;
			while (sc.hasSuperclass()) {
				if (sc.getName().equals("android.view.View")) {
					isView = true;
					break;
				}
				sc = sc.getSuperclass();
			}
			if (!isView)
				return;
		}

		// There are also some classes that implement interesting callback
		// methods.
		// We model this as follows: Whenever the user overwrites a method in an
		// Android OS class, we treat it as a potential callback.
		SootClass sc = lc.getViewClass();
		Set<String> systemMethods = new HashSet<String>(10000);
		for (SootClass parentClass : Scene.v().getActiveHierarchy()
				.getSuperclassesOf(sc)) {
			if (parentClass.getName().startsWith("android."))
				for (SootMethod sm : parentClass.getMethods())
					if (!sm.isConstructor())
						systemMethods.add(sm.getSubSignature());
		}

		// Scan for methods that overwrite parent class methods
		for (SootMethod sm : sc.getMethods())
			if (!sm.isConstructor())
				if (systemMethods.contains(sm.getSubSignature()))
					// This is a real callback method
					addCallbackMethod(callbackClass.getName(),
							new AndroidMethod(sm));
	}
}
