package com.lazarusx.revdroid.analyzer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import soot.SootMethod;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.util.SootMethodRepresentationParser;

/**
 * Class representing a single method in the Android SDK
 * 
 * @author Steven Arzt, Siegfried Rasthofer, Daniel Magin, Joern Tillmanns, Zheran Fang
 * 
 */
public class AndroidMethod extends SootMethodAndClass {

	private Set<String> permissions;

	public AndroidMethod(String methodName, String returnType, String className) {
		super(methodName, className, returnType, new ArrayList<String>());
		this.permissions = new HashSet<String>();
	}

	public AndroidMethod(String methodName, List<String> parameters,
			String returnType, String className) {
		super(methodName, className, returnType, parameters);
		this.permissions = new HashSet<String>();
	}

	public AndroidMethod(String methodName, List<String> parameters,
			String returnType, String className, Set<String> permissions) {
		super(methodName, className, returnType, parameters);
		this.permissions = new HashSet<String>();
	}

	public AndroidMethod(SootMethod sm) {
		super(sm);
		this.permissions = new HashSet<String>();
	}

	public AndroidMethod(SootMethodAndClass methodAndClass) {
		super(methodAndClass);
		this.permissions = new HashSet<String>();
	}

	public Set<String> getPermissions() {
		return this.permissions;
	}

	public void addPermission(String permission) {
		this.permissions.add(permission);
	}

	@Override
	public String toString() {
		String s = getSignature();
		for (String perm : permissions)
			s += " " + perm;

		return s;
	}

	@Override
	public boolean equals(Object another) {
		if (another instanceof AndroidMethod) {
			AndroidMethod anotherMethod = (AndroidMethod) another;

			return (anotherMethod.getClassName().equals(this.getClassName())
					&& anotherMethod.getMethodName().equals(this.getMethodName()) 
					&& anotherMethod.getReturnType().equals(this.getReturnType())
					&& anotherMethod.getParameters().equals(this.getParameters()));
		}

		return false;
	}

	public String getSignatureAndPermissions() {
		String s = getSignature();
		for (String perm : permissions)
			s += " " + perm;
		return s;
	}

	/***
	 * Static method to create AndroidMethod from Soot method signature
	 * 
	 * @param signature
	 *            The Soot method signature
	 * @return The new AndroidMethod object
	 */
	public static AndroidMethod createFromSignature(String signature) {
		if (!signature.startsWith("<"))
			signature = "<" + signature;
		if (!signature.endsWith(">"))
			signature = signature + ">";

		SootMethodAndClass smac = SootMethodRepresentationParser.v()
				.parseSootMethodString(signature);
		return new AndroidMethod(smac.getMethodName(), smac.getParameters(),
				smac.getReturnType(), smac.getClassName());
	}
}
