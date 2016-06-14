package org.crypto.pir.util;

/**
 *    PPTI ( Privacy Preserving Threat Intelligence) is research project.
 *
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation; either
 *    version 2 of the License, or (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public
 *    License along with this library; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **/
public class PerfMeter {
    public int fileLimit;

    // Time Complexity
    public long prepareDB;
    public long queryGen;
    public long processQuery;
    public long processResponse;

    // Space Complexity
    public long querySize;
    public long responseSize;

    @Override
    public String toString(){
        return prepareDB +"," + queryGen + "," + processQuery +"," + processResponse + "," + querySize + "," + responseSize;
    }
}
