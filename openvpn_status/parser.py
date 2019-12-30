from __future__ import absolute_import

from six import Iterator, next, text_type

from .models import Status, Client, Routing
from .descriptors import iter_descriptors, AssignmentValueError


class LogParser(Iterator):
    """The parser for parsing OpenVPN status log.

    This kind of parser is stateful. So the :meth:`LogParser.parse` could be
    called once in the same instance of parser.
    """

    list_separator = u','
    line_separator = u'\n'
    terminator = u'END'

    def __init__(self, lines):
        self.lines = iter(lines)
        self._last_line = None
        self._rollback = False

    def __next__(self):
        if self._rollback:
            self._rollback = False
            return self._last_line
        while True:
            line = next(self.lines).strip()
            if line:
                self._last_line = line
                return line

    @classmethod
    def fromstring(cls, content):
        """Creates a parser from content of log.

        :param str content: The log content.
        :return: The parser instance.
        """
        return cls(content.strip().split(cls.line_separator))

    def rollback(self):
        self._rollback = True

    def expect_header(self, header) -> list:
        while True:
            try:
                line: str = next(self)
            except StopIteration:
                raise ParsingError('expected %r but got end of input' % header)

            if line.startswith(f'HEADER,{header}'):
                labels = line.split(self.list_separator)[1:]
                if len(labels) == 1:
                    raise ParsingError('expected list of label but got %r' % line)
                return labels

    def expect_line(self, content):
        try:
            line = next(self)
        except StopIteration:
            raise ParsingError('expected %r but got end of input' % content)
        if line != content:
            raise ParsingError('expected %r but got %r' % (content, line))

    def expect_list(self):
        try:
            line = next(self)
        except StopIteration:
            raise ParsingError('expected list but got end of input')
        splited = line.split(self.list_separator)
        if len(splited) == 1:
            raise ParsingError('expected list but got %r' % line)
        return splited

    def expect_tuple(self, name):
        try:
            line = next(self)
        except StopIteration:
            raise ParsingError('expected 2-tuple but got end of input')
        splited = line.split(self.list_separator)
        if len(splited) != 2:
            raise ParsingError('expected 2-tuple but got %r' % line)
        if splited[0] != name:
            raise ParsingError('expected 2-tuple starting with %r' % name)
        return splited[1]

    def parse(self):
        """Parses the status log.

        :raises ParsingError: if syntax error found in the log.
        :return: The :class:`.models.Status` with filled data.
        """
        try:
            return self._parse()
        except AssignmentValueError as e:
            msg = text_type(e) \
                .encode('ascii', 'backslashreplace') \
                .decode('ascii')
            raise ParsingError('expected valid format: %s' % msg)

    def _parse(self):
        status = Status()
        labels = self.expect_header(Status.client_list.label)
        status.client_list.update({
            text_type(c.common_name): c
            for c in self._parse_fields(Client, labels)})

        labels = self.expect_header(Status.routing_table.label)
        status.routing_table.update({
            text_type(r.common_name): r
            for r in self._parse_fields(Routing, labels)})

        # self.expect_line(self.terminator)
        return status

    def _parse_fields(self, cls, labels):

        descriptors = iter_descriptors(cls)
        label_to_name = {
            descriptor.label: name for name, descriptor in descriptors}

        index_to_name = {}
        for index, label in enumerate(labels):
            if label in label_to_name:
                index_to_name[index] = label_to_name[label]

        while True:
            try:
                values = self.expect_list()
                if len(values) != len(labels):
                    raise ParsingError()

            except ParsingError as list_error:
                try:
                    self.rollback()
                except ParsingError as line_error:
                    raise ParsingError(*(list_error.args + line_error.args))
                else:
                    break

            instance = cls()
            for index, name in index_to_name.items():
                setattr(instance, name, values[index])

            yield instance


class ParsingError(Exception):
    pass
