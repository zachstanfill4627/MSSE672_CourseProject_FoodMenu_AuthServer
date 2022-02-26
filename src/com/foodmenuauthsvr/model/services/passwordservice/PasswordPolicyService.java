package com.foodmenuauthsvr.model.services.passwordservice;

public class PasswordPolicyService {

	private String minLength;
	private String maxLength;
	private String charClasses;
	private String minCharClass;
	private String iterations;
	private String keyLength;
	/**
	 * @return the minLength
	 */
	public int getMinLength() {
		return Integer.parseInt(minLength);
	}
	/**
	 * @param minLength the minLength to set
	 */
	public void setMinLength(String minLength) {
		this.minLength = minLength;
	}
	/**
	 * @return the maxLength
	 */
	public int getMaxLength() {
		return Integer.parseInt(maxLength);
	}
	/**
	 * @param maxLength the maxLength to set
	 */
	public void setMaxLength(String maxLength) {
		this.maxLength = maxLength;
	}
	/**
	 * @return the charClasses
	 */
	public int getCharClasses() {
		return Integer.parseInt(charClasses);
	}
	/**
	 * @param charClasses the charClasses to set
	 */
	public void setCharClasses(String charClasses) {
		this.charClasses = charClasses;
	}
	/**
	 * @return the minCharClass
	 */
	public int getMinCharClass() {
		return Integer.parseInt(minCharClass);
	}
	/**
	 * @param minCharClass the minCharClass to set
	 */
	public void setMinCharClass(String minCharClass) {
		this.minCharClass = minCharClass;
	}
	/**
	 * @return the iterations
	 */
	public int getIterations() {
		return Integer.parseInt(iterations);
	}
	/**
	 * @param iterations the iterations to set
	 */
	public void setIterations(String iterations) {
		this.iterations = iterations;
	}
	/**
	 * @return the keyLength
	 */
	public int getKeyLength() {
		return Integer.parseInt(keyLength);
	}
	/**
	 * @param keyLength the keyLength to set
	 */
	public void setKeyLength(String keyLength) {
		this.keyLength = keyLength;
	}
	
	
	
	
}
