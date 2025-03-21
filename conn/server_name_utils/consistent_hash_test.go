/*
 * Copyright (c) 2025. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package server_name_utils

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

var maxMinus5 = uint32(math.MaxUint32 - 5)

func testHash(value string) uint32 {
	switch value {
	case "max-5":
		return maxMinus5
	default:
		hash, _ := strconv.ParseUint(value, 10, 32)
		return uint32(hash)
	}
}

func TestConsistentHash(t *testing.T) {
	assert := assert.New(t)

	values := []string{"70", "max-5", "10"}
	hashedValues := sortValuesByHash(values, testHash)
	assert.Equal([]HashedValue{{"10", 10}, {"70", 70}, {"max-5", maxMinus5}}, hashedValues)
	assert.Equal("70", findClosestValue("68", hashedValues, testHash))
	assert.Equal("70", findClosestValue("72", hashedValues, testHash))
	assert.Equal("max-5", findClosestValue("2", hashedValues, testHash))
	assert.Equal("10", findClosestValue("6", hashedValues, testHash))
}