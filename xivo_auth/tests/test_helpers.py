# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

import unittest

from hamcrest import assert_that, contains_inanyorder, empty

from ..helpers import LazyTemplateRenderer


class TestLazyTemplateRenderer(unittest.TestCase):

    def test_render_no_templates(self):
        renderer = LazyTemplateRenderer([], None)

        acls = renderer.render()

        assert_that(acls, empty())

    def test_render_no_substitution(self):
        expected = [
            'confd.user.#',
            'dird.me.#',
        ]
        renderer = LazyTemplateRenderer(expected, None)

        acls = renderer.render()

        assert_that(acls, contains_inanyorder(*expected))

    def test_multi_line_template(self):
        def get():
            return {
                'lines': [1, 42],
            }

        templates = [
            'dird.me.#',
            '{% for line in lines %}\nconfd.lines.{{ line }}.#\n{% endfor %}',
        ]
        renderer = LazyTemplateRenderer(templates, get)

        acls = renderer.render()

        expected = [
            'confd.lines.1.#',
            'confd.lines.42.#',
            'dird.me.#',
        ]
        assert_that(acls, contains_inanyorder(*expected))
