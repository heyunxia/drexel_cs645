/**
 * StatisticsManager.java
 */
package mitm;

public class StatisticsManager
{

    private int m_reqCount = 0;

    public void incrementCounter() {
	m_reqCount++;
    }

    public int getCounterValue() {
	return m_reqCount;
    }
} 
